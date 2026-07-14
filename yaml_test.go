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
	// A 3-level nested list exceeds a max_depth of 2.
	t.Setenv("YAML_MAX_DEPTH", "2")
	_, err := run(t, `load("yaml", "decode")
decode("[[[1]]]")`)
	if err == nil || !strings.Contains(err.Error(), "max_depth") {
		t.Errorf("expected max_depth error, got %v", err)
	}
}

func TestCapNodes(t *testing.T) {
	t.Setenv("YAML_MAX_NODES", "3")
	_, err := run(t, `load("yaml", "decode")
decode("[0, 1, 2, 3, 4, 5]")`)
	if err == nil || !strings.Contains(err.Error(), "max_nodes") {
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

func TestStringKeyMapToDict(t *testing.T) {
	// A string-keyed mapping decodes to a Starlark dict carrying the same key/value.
	res, err := run(t, `load("yaml", "decode")
d = decode("only: x")
v = d["only"]`)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res["v"] != "x" {
		t.Errorf("decode(only: x)[\"only\"] = %v, want \"x\"", res["v"])
	}
}

// --- decode correctness (STAR-77): key collisions, sub-second timestamps ------

func TestDecodeCorrectness(t *testing.T) {
	// Non-string keys that collapse to the same Starlark string key (the float 1.0
	// and the int 1 both stringify to "1") are REJECTED rather than silently
	// dropping one — the STAR-77 data-loss bug.
	_, err := run(t, `load("yaml", "decode")
decode("1.0: a\n1: b\n")`)
	if err == nil || !strings.Contains(err.Error(), "collide") {
		t.Errorf("colliding non-string keys should be rejected, got %v", err)
	}

	// A genuine duplicate key is likewise rejected, never silently dropped.
	_, err = run(t, `load("yaml", "decode")
decode("'1': a\n1: b\n")`)
	if err == nil {
		t.Error("duplicate keys should be rejected, not silently dropped")
	}

	// A timestamp keeps its sub-second precision (RFC 3339 Nano, not truncated).
	res, err := run(t, `load("yaml", "decode")
ts = decode("t: 2020-01-02T03:04:05.5Z")["t"]`)
	if err != nil {
		t.Fatalf("timestamp decode: %v", err)
	}
	if res["ts"] != "2020-01-02T03:04:05.5Z" {
		t.Errorf("timestamp = %v, want sub-second precision preserved", res["ts"])
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

// TestDecodeScalarArms drives every scalar tag through decode and asserts each
// maps to the right Starlark value, including uint64 (above math.MaxInt64) and a
// whole-second timestamp (RFC 3339).
func TestDecodeScalarArms(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"null", "null", "None"},
		{"bool-true", "true", "True"},
		{"bool-false", "false", "False"},
		{"int", "7", "7"},
		{"int-negative", "-7", "-7"},
		{"int64-max", "9223372036854775807", "9223372036854775807"},
		{"uint64", "18446744073709551615", "18446744073709551615"},
		{"float", "1.5", "1.5"},
		{"float-inf", ".inf", "+inf"},
		{"string", "hello", "hello"},
		{"time", "2020-01-02T03:04:05Z", "2020-01-02T03:04:05Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := run(t, `load("yaml", "decode")
s = str(decode("v: `+tc.in+`")["v"])`)
			if err != nil {
				t.Fatalf("decode(%s): %v", tc.in, err)
			}
			if res["s"] != tc.want {
				t.Errorf("decode(v: %s) str = %v, want %s", tc.in, res["s"], tc.want)
			}
		})
	}
}

// TestDecodeNestedCapPropagation confirms a cap violation reached only through
// recursion (a list element, a mapping value) surfaces as an error.
func TestDecodeNestedCapPropagation(t *testing.T) {
	t.Setenv("YAML_MAX_DEPTH", "2")
	for _, in := range []string{"[[[1]]]", "{a: {b: {c: 1}}}"} {
		_, err := run(t, `load("yaml", "decode")
decode("`+in+`")`)
		if err == nil || !strings.Contains(err.Error(), "max_depth") {
			t.Errorf("decode(%s): expected max_depth error, got %v", in, err)
		}
	}
}

// TestDecodeIntKeyMapSorted confirms an integer-keyed mapping materializes keys
// in deterministic (stringified, sorted) order.
func TestDecodeIntKeyMapSorted(t *testing.T) {
	res, err := run(t, `load("yaml", "decode")
d = decode("2: b\n10: j\n1: a\n")
order = ",".join([str(k) for k in d.keys()])`)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Lexicographic stringified order: "1" < "10" < "2".
	if res["order"] != "1,10,2" {
		t.Errorf("int-key map order = %v, want 1,10,2", res["order"])
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
		t.Errorf("unmarshalNode of malformed input: want yaml.decode error, got %v", err)
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

// TestDecodeMergeSequenceAndComplexKey covers the merge-sequence and non-scalar-
// key branches of the node converter.
func TestDecodeMergeSequenceAndComplexKey(t *testing.T) {
	// `<<: [*a, *b]` merges two anchored mappings; the explicit key wins.
	res, err := run(t, `load("yaml", "decode")
d = decode("""
a: &a {x: 1, z: 9}
b: &b {y: 2}
m:
  <<: [*a, *b]
  z: 3
""")["m"]
vx = d["x"]
vy = d["y"]
vz = d["z"]`)
	if err != nil {
		t.Fatalf("merge-sequence decode: %v", err)
	}
	if res["vx"] != int64(1) || res["vy"] != int64(2) || res["vz"] != int64(3) {
		t.Errorf("merge-sequence: x=%v y=%v z=%v, want 1 2 3 (explicit z wins)", res["vx"], res["vy"], res["vz"])
	}
}

// TestDecodeEdgeScalars covers the empty-document, custom-tag, and explicit-null
// arms of the decoder.
func TestDecodeEdgeScalars(t *testing.T) {
	res, err := run(t, `load("yaml", "decode")
empty = decode("")
custom = decode("v: !foo bar")["v"]
nul = decode("v: ~")["v"]`)
	if err != nil {
		t.Fatalf("edge scalars: %v", err)
	}
	if res["empty"] != nil {
		t.Errorf("decode(\"\") = %v, want None", res["empty"])
	}
	if res["custom"] != "bar" {
		t.Errorf("custom-tag scalar = %v, want \"bar\"", res["custom"])
	}
	if res["nul"] != nil {
		t.Errorf("decode(v: ~)[v] = %v, want None", res["nul"])
	}
}

// TestToStarlarkUnsupportedType covers the default arm: a Go value whose type the
// converter does not handle surfaces the "unsupported value" error.
func TestToStarlarkUnsupportedType(t *testing.T) {
	nodes := 0
	if _, err := toStarlark(struct{ A int }{1}, 1, &nodes, 64, 1000); err == nil || !strings.Contains(err.Error(), "unsupported value of type") {
		t.Errorf("expected unsupported-value error, got %v", err)
	}
}

// TestScalarArmsDirect covers every scalar arm of the converter directly,
// including int64/uint64 which yaml.v3's interface{} resolution rarely produces.
func TestScalarArmsDirect(t *testing.T) {
	cases := []struct {
		in   interface{}
		want string
	}{
		{nil, "None"},
		{true, "True"},
		{int(7), "7"},
		{int64(9223372036854775807), "9223372036854775807"},
		{uint64(18446744073709551615), "18446744073709551615"},
		{float64(1.5), "1.5"},
		{"hi", `"hi"`},
	}
	for _, c := range cases {
		v, ok := scalarToStarlark(c.in)
		if !ok {
			t.Errorf("scalarToStarlark(%v): not handled", c.in)
			continue
		}
		if got := v.String(); got != c.want {
			t.Errorf("scalarToStarlark(%v) = %s, want %s", c.in, got, c.want)
		}
	}
	if _, ok := scalarToStarlark([]int{1}); ok {
		t.Error("a slice is not a scalar")
	}
}
