// Package yaml provides a Starlark module for decoding and encoding YAML.
//
// Decoding is hardened against malicious documents: the input size, nesting
// depth, total node count, and parse wall-clock time are all bounded (capwalk +
// a decode deadline for yaml.v3's super-linear parse), and parse panics are
// recovered into errors. Encoding is fenced by max_depth so a deeply-nested
// value can't drive marshalling into a fatal stack overflow. YAML's
// bare-timestamp footgun is tamed — values that the parser would turn into a Go
// time.Time (e.g. `2020-01-01`) are surfaced as RFC 3339 strings, never as a
// surprise opaque value.
package yaml

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/1set/starlet"
	"github.com/1set/starlet/dataconv"
	"github.com/1set/starlet/dataconv/types"
	"github.com/starpkg/base"
	"github.com/starpkg/base/util"
	startime "go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	goyaml "gopkg.in/yaml.v3"
)

// ModuleName is the name used in Starlark's load() for this module.
const ModuleName = "yaml"

const (
	configKeyMaxDepth       = "max_depth"
	configKeyMaxNodes       = "max_nodes"
	configKeyMaxInputBytes  = "max_input_bytes"
	configKeyMaxTime        = "max_time"
	configKeyMaxEncodeDepth = "max_encode_depth"
)

const (
	defaultMaxDepth      = 64
	defaultMaxNodes      = 100000
	defaultMaxInputBytes = 5 << 20 // 5 MiB
	// defaultMaxTime bounds a single decode's wall-clock time. 0 = no
	// module-level limit (still bounded by the thread context deadline, if the
	// host set one). Default 0 keeps historical behavior.
	defaultMaxTime = 0.0
	// defaultMaxEncodeDepth is the stack-safety fence for encode: a value nested
	// deeper than this is rejected before it can drive dataconv.Unmarshal or
	// yaml.v3's Marshal into a fatal, uncatchable stack overflow. It is generous
	// (real documents nest <100 deep) yet far below the ~millions-deep recursion
	// that would exhaust the Go stack.
	defaultMaxEncodeDepth = 10000
)

var (
	none             = starlark.None
	errDecodeTimeout = errors.New("yaml.decode: parsing exceeded the time limit")
	errEncodeDepth   = errors.New("yaml.encode: value is too deeply nested to encode safely")
)

// Module wraps a ConfigurableModule with YAML functions.
type Module struct {
	cfgMod *base.ConfigurableModule
	ext    *base.ConfigurableModuleExt
}

// NewModule creates a new Module with default configuration.
func NewModule() *Module {
	cm, _ := base.NewConfigurableModuleWithConfigOptions(
		genConfigOption(configKeyMaxDepth, "Maximum nesting depth when decoding", defaultMaxDepth),
		genConfigOption(configKeyMaxNodes, "Maximum total nodes when decoding", defaultMaxNodes),
		genConfigOption(configKeyMaxInputBytes, "Maximum input size in bytes when decoding", defaultMaxInputBytes),
		// max_time bounds a single decode's wall-clock time. max_nodes is a
		// POST-parse fence — it can't bound yaml.v3's super-linear PARSE time, so a
		// document under the byte cap can still burn CPU for a long time. HOST-ONLY:
		// a script must not be able to disable the limit.
		genConfigOption(configKeyMaxTime, "Maximum wall-clock seconds for a single decode (0 = no module limit)", defaultMaxTime).
			SetHostOnly(true),
		// max_encode_depth is a stack-safety fence, NOT the convenience max_depth
		// cap: it must be HOST-ONLY so a script can't set_max_encode_depth(0) to
		// disable the overflow protection. Its default is generous, so it never
		// rejects a realistically-shaped value.
		genConfigOption(configKeyMaxEncodeDepth, "Maximum value nesting depth when encoding (stack-safety fence)", defaultMaxEncodeDepth).
			SetHostOnly(true),
	)
	return &Module{cfgMod: cm, ext: cm.Extend()}
}

func (m *Module) maxTime() float64 {
	return m.ext.GetFloat(configKeyMaxTime, defaultMaxTime)
}

func (m *Module) maxEncodeDepth() int {
	if v := m.ext.GetInt(configKeyMaxEncodeDepth); v > 0 {
		return v
	}
	return defaultMaxEncodeDepth
}

func genConfigOption[T any](name, description string, defaultValue T) *base.ConfigOption[T] {
	return base.NewNamedConfigOption(ModuleName, name, description, defaultValue)
}

// LoadModule returns the Starlark module loader.
func (m *Module) LoadModule() starlet.ModuleLoader {
	funcs := starlark.StringDict{
		"decode": starlark.NewBuiltin(ModuleName+".decode", m.decode),
		"encode": starlark.NewBuiltin(ModuleName+".encode", m.encode),
	}
	return m.cfgMod.LoadModule(ModuleName, funcs)
}

// decode(text) -> value
func (m *Module) decode(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text types.StringOrBytes
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &text); err != nil {
		return none, err
	}
	maxBytes := m.ext.GetInt(configKeyMaxInputBytes)
	if maxBytes > 0 && len(text.GoString()) > maxBytes {
		return none, fmt.Errorf("yaml.decode: input exceeds max_input_bytes (%d)", maxBytes)
	}
	maxDepth := m.ext.GetInt(configKeyMaxDepth)
	maxNodes := m.ext.GetInt(configKeyMaxNodes)

	// Bound the parse's wall-clock time: max_input_bytes bounds size and
	// max_nodes bounds the materialized result, but neither bounds yaml.v3's
	// super-linear PARSE time. The input is an immutable []byte, so running the
	// parse in a goroutine shares nothing with an abandoned timeout goroutine.
	parsed, err := unmarshalBounded(thread, m.maxTime(), []byte(text.GoString()), maxDepth, maxNodes)
	if err != nil {
		return none, err
	}
	nodes := 0
	return toStarlark(parsed, 1, &nodes, maxDepth, maxNodes)
}

// unmarshalBounded runs unmarshal under a wall-clock deadline (the thread context
// plus, if positive, max_time), returning errDecodeTimeout when it trips.
// yaml.v3's Unmarshal is synchronous with no context support, so it runs in a
// goroutine; on timeout the abandoned goroutine keeps parsing until yaml.v3
// finishes (a hard CPU bound needs an OS/sandbox limit), but it only reads the
// immutable input, sharing nothing with the caller.
func unmarshalBounded(thread *starlark.Thread, timeout float64, data []byte, maxDepth, maxNodes int) (interface{}, error) {
	ctx, cancel := util.OpContext(thread, util.DurationFromSeconds(timeout))
	defer cancel()
	if ctx.Err() != nil {
		return nil, errDecodeTimeout
	}

	type result struct {
		v   interface{}
		err error
	}
	ch := make(chan result, 1) // buffered so an abandoned goroutine never blocks
	go func() {
		v, err := unmarshalWithLimits(data, maxDepth, maxNodes) // unmarshal recovers panics internally
		ch <- result{v, err}
	}()

	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		return nil, errDecodeTimeout
	}
}

// encode(value) -> str
func (m *Module) encode(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "value", &value); err != nil {
		return none, err
	}
	// Fence the encode by nesting depth BEFORE lowering to Go. Both
	// dataconv.Unmarshal (below) and yaml.v3's Marshal recurse over the value, so
	// a deeply-nested value would exhaust the Go stack (a fatal, uncatchable
	// overflow) in one of them. checkStarlarkDepth walks the Starlark value
	// itself — covering dicts/lists/tuples/sets and host-wrapped iterables — and
	// bails at maxDepth+1, so the check never recurses deeper than the limit.
	if err := checkStarlarkDepth(value, 1, m.maxEncodeDepth()); err != nil {
		return none, err
	}
	goVal, err := dataconv.Unmarshal(value)
	if err != nil {
		return none, fmt.Errorf("yaml.encode: %w", err)
	}
	out, err := marshal(goVal)
	if err != nil {
		return none, err
	}
	return starlark.String(out), nil
}

// checkStarlarkDepth rejects a value whose container nesting exceeds maxDepth. It
// mirrors the recursion of dataconv.Unmarshal (and yaml.v3's Marshal) over the
// Starlark value — mappings, iterables, and struct/module attributes — so an
// over-deep value is rejected before either can recurse into it. It walks
// through the starlark.Value interface, so it also covers host-backed
// iterables/mappings/structs a Go-type switch would miss. It returns as soon as
// the limit is exceeded, so its own recursion is bounded by maxDepth and cannot
// itself overflow. Scalars are handled first, so a scalar's own attribute
// methods (a String is HasAttrs) don't make it look like a container.
func checkStarlarkDepth(v starlark.Value, depth, maxDepth int) error {
	if maxDepth > 0 && depth > maxDepth {
		return errEncodeDepth
	}
	switch c := v.(type) {
	case starlark.NoneType, starlark.Bool, starlark.Int, starlark.Float, starlark.String, starlark.Bytes, startime.Time:
		return nil // leaf scalars (dataconv does not recurse into these)
	case starlark.IterableMapping:
		return checkMappingDepth(c, depth, maxDepth)
	case starlark.Iterable:
		return checkIterableDepth(c, depth, maxDepth)
	case starlark.HasAttrs:
		return checkAttrsDepth(c, depth, maxDepth) // struct / module / GoStruct
	}
	return nil
}

// checkAttrsDepth recurses into each attribute value of a struct-like value
// (starlarkstruct.Struct / Module), mirroring dataconv's iterAttrs.
func checkAttrsDepth(c starlark.HasAttrs, depth, maxDepth int) error {
	for _, name := range c.AttrNames() {
		attr, err := c.Attr(name)
		if err != nil || attr == nil {
			continue
		}
		if err := checkStarlarkDepth(attr, depth+1, maxDepth); err != nil {
			return err
		}
	}
	return nil
}

// checkMappingDepth recurses into each key and value of a mapping (dict or
// host-backed mapping) — yaml.v3 marshals both, so both add depth.
func checkMappingDepth(c starlark.IterableMapping, depth, maxDepth int) error {
	for _, item := range c.Items() { // item = (key, value)
		if err := checkStarlarkDepth(item[0], depth+1, maxDepth); err != nil {
			return err
		}
		if err := checkStarlarkDepth(item[1], depth+1, maxDepth); err != nil {
			return err
		}
	}
	return nil
}

// checkIterableDepth recurses into each element of a non-mapping iterable
// (list / tuple / set / host-backed slice).
func checkIterableDepth(c starlark.Iterable, depth, maxDepth int) error {
	it := c.Iterate()
	defer it.Done()
	var e starlark.Value
	for it.Next(&e) {
		if err := checkStarlarkDepth(e, depth+1, maxDepth); err != nil {
			return err
		}
	}
	return nil
}

// unmarshal parses YAML into a generic value, recovering panics into errors.
func unmarshal(data []byte) (interface{}, error) {
	return unmarshalWithLimits(data, defaultMaxDepth, defaultMaxNodes)
}

func unmarshalWithLimits(data []byte, maxDepth, maxNodes int) (v interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			v, err = nil, fmt.Errorf("yaml.decode: parse panic: %v", r)
		}
	}()
	var root goyaml.Node
	if uerr := goyaml.Unmarshal(data, &root); uerr != nil {
		return nil, fmt.Errorf("yaml.decode: %w", uerr)
	}
	walk := yamlWalk{maxDepth: maxDepth, maxNodes: maxNodes, active: make(map[*goyaml.Node]bool)}
	return walk.value(&root, 1)
}

// marshal encodes a Go value to YAML, recovering panics into errors.
func marshal(v interface{}) (s string, err error) {
	defer func() {
		if r := recover(); r != nil {
			s, err = "", fmt.Errorf("yaml.encode: encode panic: %v", r)
		}
	}()
	b, merr := goyaml.Marshal(exactEncodeValue(v))
	if merr != nil {
		return "", fmt.Errorf("yaml.encode: %w", merr)
	}
	return string(b), nil
}

// toStarlark converts a decoded Go value to a Starlark value, enforcing the
// depth and node caps and taming bare timestamps.
func toStarlark(v interface{}, depth int, nodes *int, maxDepth, maxNodes int) (starlark.Value, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("yaml.decode: nesting exceeds max_depth (%d)", maxDepth)
	}
	*nodes++
	if *nodes > maxNodes {
		return nil, fmt.Errorf("yaml.decode: node count exceeds max_nodes (%d)", maxNodes)
	}
	if sv, ok := scalarToStarlark(v); ok {
		return sv, nil
	}
	switch x := v.(type) {
	case []interface{}:
		return seqToStarlark(x, depth, nodes, maxDepth, maxNodes)
	case map[string]interface{}:
		return stringMapToStarlark(x, depth, nodes, maxDepth, maxNodes)
	case map[interface{}]interface{}:
		return anyMapToStarlark(x, depth, nodes, maxDepth, maxNodes)
	default:
		return nil, fmt.Errorf("yaml.decode: unsupported value of type %T", v)
	}
}

// scalarToStarlark converts a YAML scalar Go value; ok is false for a container
// or unsupported type.
func scalarToStarlark(v interface{}) (starlark.Value, bool) {
	switch x := v.(type) {
	case nil:
		return starlark.None, true
	case bool:
		return starlark.Bool(x), true
	case string:
		return starlark.String(x), true
	case time.Time:
		// Tame YAML's bare-timestamp footgun: surface as an RFC 3339 string, WITH
		// sub-second precision (RFC3339Nano) so a fractional second is not lost.
		return starlark.String(x.Format(time.RFC3339Nano)), true
	}
	return numericToStarlark(v)
}

// numericToStarlark converts a numeric scalar (yaml.v3 yields int/int64/uint64/
// float64); ok is false for a non-numeric value.
func numericToStarlark(v interface{}) (starlark.Value, bool) {
	switch x := v.(type) {
	case *big.Int:
		return starlark.MakeBigInt(new(big.Int).Set(x)), true
	case int:
		return starlark.MakeInt(x), true
	case int64:
		return starlark.MakeInt64(x), true
	case uint64:
		return starlark.MakeUint64(x), true
	case float64:
		return starlark.Float(x), true
	}
	return nil, false
}

// seqToStarlark converts a sequence to a Starlark list.
func seqToStarlark(x []interface{}, depth int, nodes *int, maxDepth, maxNodes int) (starlark.Value, error) {
	elems := make([]starlark.Value, 0, len(x))
	for _, e := range x {
		sv, err := toStarlark(e, depth+1, nodes, maxDepth, maxNodes)
		if err != nil {
			return nil, err
		}
		elems = append(elems, sv)
	}
	return starlark.NewList(elems), nil
}

// stringMapToStarlark materializes a string-keyed map as a dict in sorted-key order.
func stringMapToStarlark(x map[string]interface{}, depth int, nodes *int, maxDepth, maxNodes int) (starlark.Value, error) {
	keys := make([]string, 0, len(x))
	for k := range x {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	d := starlark.NewDict(len(keys))
	for _, k := range keys {
		sv, err := toStarlark(x[k], depth+1, nodes, maxDepth, maxNodes)
		if err != nil {
			return nil, err
		}
		if err := d.SetKey(starlark.String(k), sv); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// anyMapToStarlark materializes a non-string-keyed map. Keys are stringified in
// deterministic (sorted) order; two keys that collapse to the SAME Starlark
// string key (e.g. the float 1.0 and the int 1, both "1") are rejected rather
// than silently dropping one — the STAR-77 data-loss bug.
func anyMapToStarlark(x map[interface{}]interface{}, depth int, nodes *int, maxDepth, maxNodes int) (starlark.Value, error) {
	type kv struct {
		key string
		val interface{}
	}
	items := make([]kv, 0, len(x))
	for k, val := range x {
		items = append(items, kv{fmt.Sprintf("%v", k), val})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })
	seen := make(map[string]struct{}, len(items))
	for _, it := range items {
		if _, dup := seen[it.key]; dup {
			return nil, fmt.Errorf("yaml.decode: distinct map keys collide as %q after stringification", it.key)
		}
		seen[it.key] = struct{}{}
	}
	d := starlark.NewDict(len(items))
	for _, it := range items {
		sv, err := toStarlark(it.val, depth+1, nodes, maxDepth, maxNodes)
		if err != nil {
			return nil, err
		}
		if err := d.SetKey(starlark.String(it.key), sv); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// yamlWalk converts the syntax tree before yaml.v3 can narrow large integers to
// float64. Limits apply while aliases and merges expand, before materialization.
type yamlWalk struct {
	maxDepth, maxNodes, nodes int
	aliasDepth, aliasNodes    int
	active                    map[*goyaml.Node]bool
}

type yamlMapKey struct{ kind, text string }

func (k yamlMapKey) String() string { return k.text }

func (w *yamlWalk) value(n *goyaml.Node, depth int) (interface{}, error) {
	if n.Kind == 0 {
		return nil, nil
	}
	if n.Kind == goyaml.DocumentNode {
		return w.value(n.Content[0], depth)
	}
	if err := w.account(n, depth); err != nil {
		return nil, err
	}
	w.active[n] = true
	defer delete(w.active, n)
	switch n.Kind {
	case goyaml.AliasNode:
		w.aliasDepth++
		defer func() { w.aliasDepth-- }()
		return w.value(n.Alias, depth)
	case goyaml.ScalarNode:
		return yamlScalar(n)
	case goyaml.SequenceNode:
		return w.sequence(n, depth)
	case goyaml.MappingNode:
		return w.mapping(n, depth)
	}
	return nil, errors.New("yaml.decode: unsupported node")
}

func (w *yamlWalk) account(n *goyaml.Node, depth int) error {
	if depth > w.maxDepth {
		return fmt.Errorf("yaml.decode: nesting exceeds max_depth (%d)", w.maxDepth)
	}
	w.nodes++
	if w.aliasDepth > 0 {
		w.aliasNodes++
	}
	// Preserve yaml.v3's amplification guard as well as the host node cap.
	allowed := aliasAllowance(w.nodes)
	if w.nodes > 1000 && float64(w.aliasNodes)/float64(w.nodes) > allowed {
		return errors.New("yaml.decode: excessive aliasing")
	}
	if w.nodes > w.maxNodes {
		return fmt.Errorf("yaml.decode: node count exceeds max_nodes (%d)", w.maxNodes)
	}
	if w.active[n] {
		return errors.New("yaml.decode: cyclic alias")
	}
	return nil
}

func aliasAllowance(nodes int) float64 {
	allowed := 0.99
	if nodes > 400000 {
		allowed -= 0.89 * float64(nodes-400000) / 3600000
	}
	if allowed < 0.10 {
		return 0.10
	}
	return allowed
}

func (w *yamlWalk) sequence(n *goyaml.Node, depth int) (interface{}, error) {
	out := make([]interface{}, 0, len(n.Content))
	for _, child := range n.Content {
		v, err := w.value(child, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func isIntegerNode(n *goyaml.Node) bool {
	switch n.Tag {
	case "!!int":
		return true
	case "!!str":
		return n.Style == 0
	case "!!float":
		return n.Style == 0 && !strings.ContainsAny(n.Value, ".eE")
	}
	return false
}

func yamlScalar(n *goyaml.Node) (interface{}, error) {
	// Quoted numbers and explicitly tagged floats retain their declared types.
	if isIntegerNode(n) {
		text := strings.ReplaceAll(n.Value, "_", "")
		if value, ok := new(big.Int).SetString(text, 0); ok {
			return value, nil
		}
		if value, ok := new(big.Int).SetString(text, 10); ok {
			return value, nil
		}
	}
	var value interface{}
	if err := n.Decode(&value); err != nil {
		return nil, fmt.Errorf("yaml.decode: %w", err)
	}
	return value, nil
}

func scalarKey(n *goyaml.Node) (yamlMapKey, error) {
	if n.Kind == goyaml.AliasNode {
		n = n.Alias
	}
	if n.Kind != goyaml.ScalarNode {
		return yamlMapKey{}, errors.New("yaml.decode: non-scalar mapping key")
	}
	v, err := yamlScalar(n)
	if err != nil {
		return yamlMapKey{}, err
	}
	return yamlMapKey{kind: fmt.Sprintf("%T", v), text: fmt.Sprint(v)}, nil
}

func (w *yamlWalk) mapping(n *goyaml.Node, depth int) (interface{}, error) {
	out := make(map[interface{}]interface{})
	var merge *goyaml.Node
	for i := 0; i < len(n.Content); i += 2 {
		keyNode, valueNode := n.Content[i], n.Content[i+1]
		if keyNode.Tag == "!!merge" {
			if merge != nil {
				return nil, errors.New("yaml.decode: duplicate merge key")
			}
			merge = valueNode
			continue
		}
		key, err := scalarKey(keyNode)
		if err != nil {
			return nil, err
		}
		if _, duplicate := out[key]; duplicate {
			return nil, fmt.Errorf("yaml.decode: mapping keys collide as %q", key.text)
		}
		v, err := w.value(valueNode, depth+1)
		if err != nil {
			return nil, err
		}
		out[key] = v
	}
	return w.mergeMapping(out, merge, depth)
}

func (w *yamlWalk) mergeMapping(out map[interface{}]interface{}, merge *goyaml.Node, depth int) (interface{}, error) {
	if merge == nil {
		return out, nil
	}
	v, err := w.value(merge, depth+1)
	if err != nil {
		return nil, err
	}
	sources, sequence := v.([]interface{})
	if !sequence {
		sources = []interface{}{v}
	}
	for _, source := range sources {
		m, ok := source.(map[interface{}]interface{})
		if !ok {
			return nil, errors.New("yaml.decode: merge requires a mapping or sequence of mappings")
		}
		// Explicit keys win; among merge sources, the first occurrence wins.
		for key, value := range m {
			if _, exists := out[key]; !exists {
				out[key] = value
			}
		}
	}
	return out, nil
}

// exactYAMLInteger prevents yaml.v3 from treating big.Int's text marshaler as
// a quoted string. It also works in container values and numeric mapping keys.
type exactYAMLInteger string

func (n exactYAMLInteger) MarshalYAML() (interface{}, error) {
	return &goyaml.Node{Kind: goyaml.ScalarNode, Tag: "!!int", Value: string(n)}, nil
}

func exactEncodeValue(v interface{}) interface{} {
	switch v := v.(type) {
	case *big.Int:
		return exactYAMLInteger(v.String())
	case big.Int:
		return exactYAMLInteger(v.String())
	case []interface{}:
		return exactEncodeSequence(v)
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, value := range v {
			out[key] = exactEncodeValue(value)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[interface{}]interface{}, len(v))
		for key, value := range v {
			out[exactEncodeValue(key)] = exactEncodeValue(value)
		}
		return out
	}
	return v
}

func exactEncodeSequence(v []interface{}) []interface{} {
	out := make([]interface{}, len(v))
	for i, value := range v {
		out[i] = exactEncodeValue(value)
	}
	return out
}
