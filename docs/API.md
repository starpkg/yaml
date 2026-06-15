# `yaml` — Starlark API Reference

The complete reference for every script-facing builtin and configuration
accessor exposed by the `yaml` module. For an overview, installation, and a
quickstart, see the [README](../README.md).

The module exposes two top-level builtins via `load("yaml", …)` — `decode` and
`encode` — plus a set of configuration accessors (`get_<key>` / `set_<key>`)
generated from the module's options. There are no object methods: `decode`
returns plain Starlark values (`dict` / `list` / `str` / `int` / `float` /
`bool` / `None`) and `encode` returns a `str`.

## Contents

- [Functions](#functions)
- [Anchors, aliases, and merge keys](#anchors-aliases-and-merge-keys)
- [Hardening](#hardening)
- [Configuration](#configuration)

## Functions

### `decode(text)`

Parses a YAML document and returns Starlark values.

**Parameters:**

- `text` (string or bytes): The YAML document to parse.

**Returns:** A Starlark value mirroring the document:

- a YAML mapping becomes a `dict` (string keys; non-string keys are
  stringified deterministically),
- a sequence becomes a `list`, and
- scalars become `None` / `bool` / `int` / `float` / `str`.

A scalar that YAML would parse as a date or datetime is returned as an RFC 3339
`str` (see [Hardening](#hardening)). Anchors, aliases, and merge keys (`<<`) are
resolved by the parser.

**Errors:** Raises an error when the input exceeds a cap (`max_input_bytes`,
`max_depth`, or `max_nodes`), when the document is malformed, or when it decodes
to an unsupported type.

**Example:**

```python
load("yaml", "decode")

doc = decode("""
name: Ada
langs: [go, python]
nested:
  k: v
""")
doc["name"]            # => "Ada"
doc["langs"][0]        # => "go"
doc["nested"]["k"]     # => "v"

# bytes input is accepted too
decode(b"a: 1")["a"]   # => 1
```

### `encode(value)`

Serializes a Starlark `value` to a YAML `str`. The value is first lowered to a
Go value (via Starlet's `dataconv.Unmarshal`), then marshalled with
`gopkg.in/yaml.v3`. Mapping keys are emitted in sorted order.

**Parameters:**

- `value`: Any Starlark value that can be lowered to a Go value
  (`dict` / `list` / `str` / `int` / `float` / `bool` / `None`, and nestings
  thereof).

**Returns:** The YAML serialization as a `str`.

**Errors:** Raises an error if the value cannot be lowered (e.g. a
self-referential/cyclic container) or marshalled.

**Example:**

```python
load("yaml", "encode")

encode({"a": 1, "b": [1, 2]})   # => "a: 1\nb:\n    - 1\n    - 2\n"
```

## Anchors, aliases, and merge keys

YAML's cross-reference features resolve through `decode` — an alias reuses an
anchored value, and a merge key (`<<`) inherits an anchored mapping while
allowing per-key overrides:

```python
load("yaml", "decode")

doc = decode("""
defaults: &d
  timeout: 30
  retries: 3
prod:
  <<: *d        # inherit defaults
  timeout: 60   # override
""")
doc["prod"]["timeout"]   # => 60  (overridden)
doc["prod"]["retries"]   # => 3   (inherited)
```

Runaway alias expansion (a "billion laughs" bomb) is rejected as an error, not
an out-of-memory crash.

## Hardening

Decoding treats input as untrusted and enforces the following properties:

- **Bare timestamps are strings.** A scalar that YAML would parse into a date or
  datetime (e.g. `2020-01-02`) is surfaced as an RFC 3339 **string**, never a
  surprise opaque value — so `type(doc["date"]) == "string"` always holds.
- **Bounded decode (capwalk).** Decoding rejects input over `max_input_bytes`,
  nesting deeper than `max_depth`, or more than `max_nodes` total nodes —
  defusing deeply-nested and oversized inputs.
- **Alias / anchor expansion ("billion laughs").** Runaway alias expansion is
  bounded by the underlying [`gopkg.in/yaml.v3`](https://gopkg.in/yaml.v3)
  parser, which caps the work an aliased document may unfold into and surfaces
  the overflow as a decode **error**. The capwalk `max_depth` / `max_nodes` /
  `max_input_bytes` caps are an additional backstop on the materialized result.
- **No host panics.** Decode and encode recover panics into errors.
- **Deterministic order.** Mapping keys are emitted in sorted order; non-string
  keys are stringified.

## Configuration

Each module configuration option is exposed to scripts as a pair of generated
accessor builtins (loaded from the `yaml` module alongside the functions above):

- **`get_<key>()`** — returns the current value of the option.
- **`set_<key>(value)`** — sets the option (returns `None`).

An option's value resolves in priority order: an explicit `set_<key>` value, the
environment variable, then the default. These three caps are the only host
levers; they default to generous values, so existing scripts decode/encode
identically.

None of the `yaml` options are secret, so every option exposes **both**
`get_<key>` and `set_<key>`. (A secret option would expose only its `set_<key>`
accessor — never a getter — but this module has none.)

| Option | Getter | Setter | Type | Env var | Default | Description |
|--------|--------|--------|------|---------|---------|-------------|
| `max_depth` | `get_max_depth` | `set_max_depth` | int | `YAML_MAX_DEPTH` | `64` | Maximum nesting depth when decoding |
| `max_nodes` | `get_max_nodes` | `set_max_nodes` | int | `YAML_MAX_NODES` | `100000` | Maximum total nodes when decoding |
| `max_input_bytes` | `get_max_input_bytes` | `set_max_input_bytes` | int | `YAML_MAX_INPUT_BYTES` | `5242880` | Maximum input size in bytes when decoding (5 MiB) |

**Example:**

```python
load(
    "yaml",
    "decode",
    # getters
    "get_max_depth", "get_max_nodes", "get_max_input_bytes",
    # setters
    "set_max_depth", "set_max_nodes", "set_max_input_bytes",
)

set_max_depth(16)
print(get_max_depth())   # 16

# a document nested deeper than 16 now raises an error
decode("a:\n  b:\n    c: 1")
```
