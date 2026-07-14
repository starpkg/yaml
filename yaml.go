// Package yaml provides a Starlark module for decoding and encoding YAML.
//
// Decoding is hardened against malicious documents: the input size, nesting
// depth, and total node count are all bounded (capwalk), and parse panics are
// recovered into errors. YAML's bare-timestamp footgun is tamed — values that
// the parser would turn into a Go time.Time (e.g. `2020-01-01`) are surfaced as
// RFC 3339 strings, never as a surprise opaque value.
package yaml

import (
	"fmt"
	"sort"
	"time"

	"github.com/1set/starlet"
	"github.com/1set/starlet/dataconv"
	"github.com/1set/starlet/dataconv/types"
	"github.com/starpkg/base"
	"go.starlark.net/starlark"
	goyaml "gopkg.in/yaml.v3"
)

// ModuleName is the name used in Starlark's load() for this module.
const ModuleName = "yaml"

const (
	configKeyMaxDepth      = "max_depth"
	configKeyMaxNodes      = "max_nodes"
	configKeyMaxInputBytes = "max_input_bytes"
)

const (
	defaultMaxDepth      = 64
	defaultMaxNodes      = 100000
	defaultMaxInputBytes = 5 << 20 // 5 MiB
)

var none = starlark.None

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
	)
	return &Module{cfgMod: cm, ext: cm.Extend()}
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

	parsed, err := unmarshal([]byte(text.GoString()))
	if err != nil {
		return none, err
	}
	nodes := 0
	return toStarlark(parsed, 1, &nodes, maxDepth, maxNodes)
}

// encode(value) -> str
func (m *Module) encode(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "value", &value); err != nil {
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

// unmarshal parses YAML into a generic value, recovering panics into errors.
func unmarshal(data []byte) (v interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			v, err = nil, fmt.Errorf("yaml.decode: parse panic: %v", r)
		}
	}()
	if uerr := goyaml.Unmarshal(data, &v); uerr != nil {
		return nil, fmt.Errorf("yaml.decode: %w", uerr)
	}
	return v, nil
}

// marshal encodes a Go value to YAML, recovering panics into errors.
func marshal(v interface{}) (s string, err error) {
	defer func() {
		if r := recover(); r != nil {
			s, err = "", fmt.Errorf("yaml.encode: encode panic: %v", r)
		}
	}()
	b, merr := goyaml.Marshal(v)
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
