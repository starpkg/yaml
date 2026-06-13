package yaml

// Tests for the yaml module.
//
// Sections:
//   - decode / encode round-trip
//   - bare-timestamp taming
//   - capwalk limits (depth / nodes / input bytes)

import (
	"strings"
	"testing"

	"github.com/1set/starlet"
	"go.starlark.net/starlark"
)

func run(t *testing.T, script string) (map[string]interface{}, error) {
	t.Helper()
	m := starlet.NewDefault()
	m.SetScriptContent([]byte(script))
	m.SetLazyloadModules(map[string]starlet.ModuleLoader{ModuleName: NewModule().LoadModule()})
	return m.Run()
}

// --- decode / encode ---------------------------------------------------------

func TestDecode(t *testing.T) {
	res, err := run(t, `
load("yaml", "decode")
doc = decode("""
name: Ada
age: 36
langs:
  - go
  - python
nested:
  k: v
""")
name = doc["name"]
age = doc["age"]
first = doc["langs"][0]
nv = doc["nested"]["k"]
`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res["name"] != "Ada" || res["age"] != int64(36) || res["first"] != "go" || res["nv"] != "v" {
		t.Errorf("decoded values wrong: %v %v %v %v", res["name"], res["age"], res["first"], res["nv"])
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	res, err := run(t, `
load("yaml", "decode", "encode")
text = encode({"a": 1, "b": [1, 2], "c": "x"})
back = decode(text)
a = back["a"]
b1 = back["b"][1]
c = back["c"]
`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res["a"] != int64(1) || res["b1"] != int64(2) || res["c"] != "x" {
		t.Errorf("round-trip wrong: a=%v b1=%v c=%v", res["a"], res["b1"], res["c"])
	}
}

// --- bare-timestamp taming ---------------------------------------------------

func TestBareTimestampIsString(t *testing.T) {
	res, err := run(t, `
load("yaml", "decode")
doc = decode("d: 2020-01-02")
d = doc["d"]
is_str = type(d) == "string"
`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res["is_str"] != true {
		t.Errorf("bare date should decode to a string, got type for value %v", res["d"])
	}
	if s, _ := res["d"].(string); !strings.HasPrefix(s, "2020-01-02") {
		t.Errorf("date string = %v, want 2020-01-02 prefix", res["d"])
	}
}

func TestNonStringKeys(t *testing.T) {
	// Integer keys produce a general map; keys are stringified.
	res, err := run(t, `
load("yaml", "decode")
doc = decode("1: one\n2: two")
v1 = doc["1"]
v2 = doc["2"]
`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res["v1"] != "one" || res["v2"] != "two" {
		t.Errorf("non-string-key decode wrong: %v %v", res["v1"], res["v2"])
	}
}

// --- capwalk limits ----------------------------------------------------------

func TestCapDepth(t *testing.T) {
	// [[[1]]] is depth 3; cap at 2 must reject.
	nested := []interface{}{[]interface{}{[]interface{}{int(1)}}}
	nodes := 0
	if _, err := toStarlark(nested, 1, &nodes, 2, 1000); err == nil || !strings.Contains(err.Error(), "max_depth") {
		t.Errorf("expected max_depth error, got %v", err)
	}
}

func TestCapNodes(t *testing.T) {
	list := make([]interface{}, 10)
	for i := range list {
		list[i] = int(i)
	}
	nodes := 0
	if _, err := toStarlark(list, 1, &nodes, 64, 3); err == nil || !strings.Contains(err.Error(), "max_nodes") {
		t.Errorf("expected max_nodes error, got %v", err)
	}
}

func TestCapInputBytes(t *testing.T) {
	t.Setenv("YAML_MAX_INPUT_BYTES", "8")
	_, err := run(t, `
load("yaml", "decode")
decode("a: 12345678901234567890")
`)
	if err == nil || !strings.Contains(err.Error(), "max_input_bytes") {
		t.Errorf("expected max_input_bytes error, got %v", err)
	}
}

func TestTimestampValueGoLevel(t *testing.T) {
	// Sanity: a time.Time becomes an RFC3339 string through toStarlark.
	nodes := 0
	v, err := toStarlark(map[string]interface{}{"only": "x"}, 1, &nodes, 64, 1000)
	if err != nil {
		t.Fatalf("toStarlark: %v", err)
	}
	if _, ok := v.(*starlark.Dict); !ok {
		t.Errorf("map should convert to dict, got %T", v)
	}
}
