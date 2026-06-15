package yaml

// Tests for the yaml module.
//
// Sections:
//   - decode / encode round-trip
//   - bare-timestamp taming
//   - capwalk limits (depth / nodes / input bytes)
//   - defensive / error arms (unsupported toStarlark type, encode failure)
//   - anchors / aliases / merge keys
//   - comprehensive document + round-trip
//   - scalar arm coverage (Go-level toStarlark per type, nested error propagation)
//   - decode / encode error normalization (malformed input, bad args, lowering)
//   - cap configuration (disabled byte cap, byte-not-rune counting)

import (
	"math"
	"strings"
	"testing"
	"time"

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

// --- scalar arm coverage -----------------------------------------------------

// TestToStarlarkScalarArms drives every scalar arm of toStarlark directly at
// the Go level (yaml.v3 hands us int/int64/uint64/float64/string/nil/bool/
// time.Time) and asserts each maps to the right Starlark value. This pins the
// behaviour of arms that the parser rarely produces (uint64 for values above
// math.MaxInt64, int64 for ordinary integers) and confirms the time.Time arm
// formats as RFC 3339.
func TestToStarlarkScalarArms(t *testing.T) {
	ts := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		name string
		in   interface{}
		want string // String() of the resulting starlark.Value
	}{
		{"nil", nil, "None"},
		{"bool-true", true, "True"},
		{"bool-false", false, "False"},
		{"int", int(7), "7"},
		{"int-negative", int(-7), "-7"},
		{"int64", int64(9223372036854775807), "9223372036854775807"},
		{"uint64-overflow", uint64(18446744073709551615), "18446744073709551615"},
		{"float64", float64(1.5), "1.5"},
		{"float64-inf", math.Inf(1), "+inf"},
		{"string", "hello", `"hello"`},
		{"time", ts, `"2020-01-02T03:04:05Z"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes := 0
			v, err := toStarlark(tc.in, 1, &nodes, 64, 1000)
			if err != nil {
				t.Fatalf("toStarlark(%v): %v", tc.in, err)
			}
			if got := v.String(); got != tc.want {
				t.Errorf("toStarlark(%v) = %s, want %s", tc.in, got, tc.want)
			}
			if nodes != 1 {
				t.Errorf("scalar should count as exactly 1 node, got %d", nodes)
			}
		})
	}
}

// TestToStarlarkNestedErrorPropagation confirms that a cap violation reached
// only through recursion (inside a list element, a string-keyed map value, and
// a non-string-keyed map value) is surfaced as an error rather than swallowed.
func TestToStarlarkNestedErrorPropagation(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
	}{
		{"in-list", []interface{}{[]interface{}{[]interface{}{int(1)}}}},
		{"in-string-key-map", map[string]interface{}{"a": map[string]interface{}{"b": map[string]interface{}{"c": int(1)}}}},
		{"in-int-key-map", map[interface{}]interface{}{1: map[interface{}]interface{}{2: map[interface{}]interface{}{3: int(1)}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes := 0
			// maxDepth 2 rejects anything at depth 3.
			if _, err := toStarlark(tc.in, 1, &nodes, 2, 1000); err == nil || !strings.Contains(err.Error(), "max_depth") {
				t.Errorf("expected max_depth error from nested value, got %v", err)
			}
		})
	}
}

// TestToStarlarkIntKeyMapSorted confirms the non-string-key map arm stringifies
// keys and materializes them in sorted order (deterministic-order invariant).
func TestToStarlarkIntKeyMapSorted(t *testing.T) {
	nodes := 0
	v, err := toStarlark(map[interface{}]interface{}{
		2: "b", 10: "j", 1: "a",
	}, 1, &nodes, 64, 1000)
	if err != nil {
		t.Fatalf("toStarlark: %v", err)
	}
	d, ok := v.(*starlark.Dict)
	if !ok {
		t.Fatalf("want *starlark.Dict, got %T", v)
	}
	var keys []string
	for _, k := range d.Keys() {
		s, _ := starlark.AsString(k)
		keys = append(keys, s)
	}
	// Lexicographic stringified order: "1" < "10" < "2".
	want := []string{"1", "10", "2"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("int-key map order = %v, want %v", keys, want)
	}
}

// --- decode / encode error normalization -------------------------------------

// TestDecodeMalformed confirms a syntactically invalid document is surfaced as
// a "yaml.decode:" error (yaml.v3's scan/parse error wrapped), not a panic.
func TestDecodeMalformed(t *testing.T) {
	_, err := run(t, `
load("yaml", "decode")
decode("a: [1, 2")
`)
	if err == nil || !strings.Contains(err.Error(), "yaml.decode") {
		t.Errorf("expected yaml.decode error for malformed input, got %v", err)
	}
}

// TestUnmarshalErrorAndMarshalError exercises the goyaml error branches of the
// unmarshal/marshal wrappers directly at the Go level.
func TestUnmarshalErrorAndMarshalError(t *testing.T) {
	// Unmarshal of a structurally broken document returns a wrapped error.
	if _, err := unmarshal([]byte("a: [1, 2")); err == nil || !strings.Contains(err.Error(), "yaml.decode") {
		t.Errorf("unmarshal of malformed input: want yaml.decode error, got %v", err)
	}
	// Marshal of a value yaml.v3 cannot encode (a func) returns a wrapped error.
	if _, err := marshal(func() {}); err == nil || !strings.Contains(err.Error(), "yaml.encode") {
		t.Errorf("marshal of func: want yaml.encode error, got %v", err)
	}
	// Marshal of an ordinary value succeeds and produces valid YAML text.
	out, err := marshal(map[string]interface{}{"k": "v"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if out != "k: v\n" {
		t.Errorf("marshal output = %q, want %q", out, "k: v\n")
	}
}

// TestEncodeUnlowerableValue confirms a Starlark value that dataconv cannot
// lower (a builtin) is surfaced as a "yaml.encode:" error before any marshal.
func TestEncodeUnlowerableValue(t *testing.T) {
	m := NewModule()
	b := starlark.NewBuiltin(ModuleName+".encode", m.encode)
	// Pass the encode builtin itself as the value — not data-shaped.
	_, err := m.encode(&starlark.Thread{}, b, starlark.Tuple{b}, nil)
	if err == nil || !strings.Contains(err.Error(), "yaml.encode") {
		t.Errorf("expected yaml.encode lowering error, got %v", err)
	}
}

// TestDecodeBadArgs confirms argument-shape errors are clean script errors with
// the builtin name, not panics.
func TestDecodeBadArgs(t *testing.T) {
	cases := []struct {
		name   string
		script string
		want   string
	}{
		{"wrong-type", `decode(123)`, "want string or bytes"},
		{"missing", `decode()`, "missing argument for text"},
		{"too-many", `decode("a: 1", "extra")`, "want at most"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := run(t, "load(\"yaml\", \"decode\")\n"+tc.script)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("decode(%s): want error containing %q, got %v", tc.name, tc.want, err)
			}
		})
	}
}

// TestEncodeBadArgs confirms encode's argument errors are clean.
func TestEncodeBadArgs(t *testing.T) {
	_, err := run(t, `
load("yaml", "encode")
encode()
`)
	if err == nil || !strings.Contains(err.Error(), "missing argument for value") {
		t.Errorf("encode() with no arg: want missing-argument error, got %v", err)
	}
}

// TestEncodeScalar covers the successful encode path through the builtin for a
// plain scalar (not just the round-trip script), asserting exact output.
func TestEncodeScalar(t *testing.T) {
	res, err := run(t, `
load("yaml", "encode")
out = encode("hello")
`)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if got, _ := res["out"].(string); got != "hello\n" {
		t.Errorf("encode(\"hello\") = %q, want %q", got, "hello\n")
	}
}

// --- cap configuration -------------------------------------------------------

// TestInputByteCapDisabled confirms that setting max_input_bytes to 0 disables
// the byte cap (the only cap that treats <= 0 as "unlimited"), preserving the
// backward-compat behaviour of decoding an arbitrary-length document.
func TestInputByteCapDisabled(t *testing.T) {
	t.Setenv("YAML_MAX_INPUT_BYTES", "0")
	res, err := run(t, `
load("yaml", "decode")
out = decode("a: 12345678901234567890")  # 22 bytes; longer than any small cap
v = out["a"]
ty = type(v)
`)
	if err != nil {
		t.Fatalf("decode with disabled byte cap: %v", err)
	}
	// The value decodes as a Starlark int (this 20-digit number fits in uint64
	// and surfaces to Go as uint64). Disabling the cap must not error.
	if res["ty"] != "int" {
		t.Errorf("type with byte cap disabled = %v, want int", res["ty"])
	}
	if got, ok := res["v"].(uint64); !ok || got != 12345678901234567890 {
		t.Errorf("decoded value = %v (%T), want uint64 12345678901234567890", res["v"], res["v"])
	}
}

// TestInputBytesCountedAsBytes confirms max_input_bytes counts raw bytes, not
// runes: a short multibyte document can still exceed a small byte cap.
func TestInputBytesCountedAsBytes(t *testing.T) {
	t.Setenv("YAML_MAX_INPUT_BYTES", "10")
	// "a: 世界" = "a: " (3) + two 3-byte CJK runes (6) = 9 bytes -> under cap, ok.
	if _, err := run(t, `
load("yaml", "decode")
decode("a: 世界")
`); err != nil {
		t.Errorf("9-byte multibyte doc under a 10-byte cap should decode, got %v", err)
	}
	// "a: 世界世" = 3 + 9 = 12 bytes -> over the 10-byte cap.
	_, err := run(t, `
load("yaml", "decode")
decode("a: 世界世")
`)
	if err == nil || !strings.Contains(err.Error(), "max_input_bytes") {
		t.Errorf("12-byte multibyte doc over a 10-byte cap should be rejected, got %v", err)
	}
}

// TestDecodeBytesInput confirms decode accepts a bytes argument (not just str),
// exercising the StringOrBytes unpack path.
func TestDecodeBytesInput(t *testing.T) {
	res, err := run(t, `
load("yaml", "decode")
out = decode(b"a: 1\nb: two")
a = out["a"]
b = out["b"]
`)
	if err != nil {
		t.Fatalf("decode(bytes): %v", err)
	}
	if res["a"] != int64(1) || res["b"] != "two" {
		t.Errorf("decode(bytes) = a:%v b:%v, want a:1 b:two", res["a"], res["b"])
	}
}
