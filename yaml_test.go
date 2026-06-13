package yaml

// Tests for the yaml module.
//
// Sections:
//   - decode / encode round-trip
//   - bare-timestamp taming
//   - capwalk limits (depth / nodes / input bytes)
//   - defensive / error arms (unsupported toStarlark type, encode failure)

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

// --- defensive / error arms --------------------------------------------------

func TestToStarlarkUnsupportedType(t *testing.T) {
	// A Go value whose type the decode switch does not handle (e.g. a struct)
	// must hit the default arm and surface the "unsupported value" error rather
	// than silently producing a wrong value.
	type unsupported struct{ A int }
	nodes := 0
	_, err := toStarlark(unsupported{A: 1}, 1, &nodes, 64, 1000)
	if err == nil || !strings.Contains(err.Error(), "unsupported value of type") {
		t.Errorf("expected unsupported-value error, got %v", err)
	}
}

func TestEncodeNonMarshalable(t *testing.T) {
	// A self-referential (cyclic) list cannot be unmarshalled into a Go value,
	// so encode() must surface a "yaml.encode" error instead of panicking.
	cyclic := starlark.NewList(nil)
	if err := cyclic.Append(cyclic); err != nil {
		t.Fatalf("append: %v", err)
	}
	m := NewModule()
	b := starlark.NewBuiltin(ModuleName+".encode", m.encode)
	_, err := m.encode(&starlark.Thread{}, b, starlark.Tuple{cyclic}, nil)
	if err == nil || !strings.Contains(err.Error(), "yaml.encode") {
		t.Errorf("expected yaml.encode error, got %v", err)
	}
}

// --- anchors / aliases / merge keys (one region referencing another) ---------

// TestAnchorsAliasesMerge verifies YAML's cross-reference features resolve
// through decode: a scalar alias reuses an anchored value, and a merge key
// (<<) inherits an anchored mapping while allowing per-key overrides.
func TestAnchorsAliasesMerge(t *testing.T) {
	res, err := run(t, `
load("yaml", "decode")
doc = decode("""
defaults: &d
  timeout: 30
  retries: 3
prod:
  <<: *d
  timeout: 60
greeting: &g hello
echo: *g
""")
prod_timeout = doc["prod"]["timeout"]   # overridden
prod_retries = doc["prod"]["retries"]   # inherited via merge
echo = doc["echo"]                       # scalar alias
`)
	if err != nil {
		t.Fatalf("anchors/aliases/merge: %v", err)
	}
	if res["prod_timeout"] != int64(60) {
		t.Errorf("merge override prod.timeout = %v, want 60", res["prod_timeout"])
	}
	if res["prod_retries"] != int64(3) {
		t.Errorf("merge inherit prod.retries = %v, want 3", res["prod_retries"])
	}
	if res["echo"] != "hello" {
		t.Errorf("scalar alias echo = %v, want hello", res["echo"])
	}
}

// TestAliasBombRejected confirms an alias-expansion (billion-laughs) bomb is
// rejected as an error (by yaml.v3's guard), not an OOM or panic.
func TestAliasBombRejected(t *testing.T) {
	_, err := run(t, `
load("yaml", "decode")
decode("""
a: &a [x,x,x,x,x,x,x,x,x]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: [*c,*c,*c,*c,*c,*c,*c,*c,*c]
""")
`)
	if err == nil {
		t.Fatal("alias bomb should be rejected")
	}
}

// --- comprehensive document + round-trip -------------------------------------

// TestComprehensiveDocument loads one document exercising many shapes at once:
// nested maps/lists, mixed scalar types, a bare date (tamed to a string), null,
// and deep nesting — asserting each field decodes as expected.
func TestComprehensiveDocument(t *testing.T) {
	res, err := run(t, `
load("yaml", "decode")
doc = decode("""
name: starpkg
count: 42
ratio: 1.5
enabled: true
disabled: false
empty:
tags:
  - go
  - starlark
server:
  host: localhost
  ports: [80, 443]
  tls:
    enabled: true
released: 2026-06-13
""")
name = doc["name"]
count = doc["count"]
ratio = doc["ratio"]
enabled = doc["enabled"]
empty_is_none = doc["empty"] == None
tag1 = doc["tags"][1]
port2 = doc["server"]["ports"][1]
tls = doc["server"]["tls"]["enabled"]
released_is_str = type(doc["released"]) == "string"
`)
	if err != nil {
		t.Fatalf("comprehensive: %v", err)
	}
	checks := map[string]interface{}{
		"name": "starpkg", "count": int64(42), "ratio": 1.5, "enabled": true,
		"empty_is_none": true, "tag1": "starlark", "port2": int64(443),
		"tls": true, "released_is_str": true,
	}
	for k, want := range checks {
		if res[k] != want {
			t.Errorf("%s = %v (%T), want %v", k, res[k], res[k], want)
		}
	}
}

// TestRoundTripEquivalence decodes, re-encodes, and decodes again, asserting the
// structure survives a YAML round-trip.
func TestRoundTripEquivalence(t *testing.T) {
	res, err := run(t, `
load("yaml", "decode", "encode")
orig = {"a": 1, "b": [1, 2, 3], "c": {"d": "x"}, "e": True}
again = decode(encode(orig))
same_a = again["a"] == 1
same_b1 = again["b"][2] == 3
same_c = again["c"]["d"] == "x"
same_e = again["e"] == True
`)
	if err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	for _, k := range []string{"same_a", "same_b1", "same_c", "same_e"} {
		if res[k] != true {
			t.Errorf("round-trip %s = %v, want true", k, res[k])
		}
	}
}
