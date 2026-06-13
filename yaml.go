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
	return base.NewConfigOption(defaultValue).
		WithName(name).
		WithDescription(description).
		WithEnvVar("YAML_" + upper(name))
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

// unmarshal parses YAML, recovering panics into errors.
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
	switch x := v.(type) {
	case nil:
		return starlark.None, nil
	case bool:
		return starlark.Bool(x), nil
	case int:
		return starlark.MakeInt(x), nil
	case int64:
		return starlark.MakeInt64(x), nil
	case uint64:
		return starlark.MakeUint64(x), nil
	case float64:
		return starlark.Float(x), nil
	case string:
		return starlark.String(x), nil
	case time.Time:
		// Tame YAML's bare-timestamp footgun: surface as an RFC 3339 string.
		return starlark.String(x.Format(time.RFC3339)), nil
	case []interface{}:
		elems := make([]starlark.Value, 0, len(x))
		for _, e := range x {
			sv, err := toStarlark(e, depth+1, nodes, maxDepth, maxNodes)
			if err != nil {
				return nil, err
			}
			elems = append(elems, sv)
		}
		return starlark.NewList(elems), nil
	case map[string]interface{}:
		d := starlark.NewDict(len(x))
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sv, err := toStarlark(x[k], depth+1, nodes, maxDepth, maxNodes)
			if err != nil {
				return nil, err
			}
			_ = d.SetKey(starlark.String(k), sv)
		}
		return d, nil
	case map[interface{}]interface{}:
		// Non-string keys: stringify deterministically.
		type kv struct {
			key string
			val interface{}
		}
		items := make([]kv, 0, len(x))
		for k, val := range x {
			items = append(items, kv{fmt.Sprintf("%v", k), val})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })
		d := starlark.NewDict(len(items))
		for _, it := range items {
			sv, err := toStarlark(it.val, depth+1, nodes, maxDepth, maxNodes)
			if err != nil {
				return nil, err
			}
			_ = d.SetKey(starlark.String(it.key), sv)
		}
		return d, nil
	default:
		return nil, fmt.Errorf("yaml.decode: unsupported value of type %T", v)
	}
}

func upper(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}
