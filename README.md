# 📄 `yaml` — YAML for Starlark

[![Go Reference](https://pkg.go.dev/badge/github.com/starpkg/yaml.svg)](https://pkg.go.dev/github.com/starpkg/yaml)

Decode and encode [YAML](https://yaml.org/) from Starlark, built on
[gopkg.in/yaml.v3](https://gopkg.in/yaml.v3).

Decoding is **hardened**: input size, nesting depth, and total node count are
bounded; parse panics become errors; and YAML's bare-timestamp footgun is tamed.

## Installation

```bash
go get github.com/starpkg/yaml
```

## Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `decode` | `decode(text) -> value` | Parse YAML into Starlark values (dict/list/str/int/float/bool/None). |
| `encode` | `encode(value) -> str` | Serialize a Starlark value to YAML text. |

## Usage

```python
load("yaml", "decode", "encode")

doc = decode("""
name: Ada
langs: [go, python]
nested:
  k: v
""")
doc["name"]            # => "Ada"
doc["langs"][0]        # => "go"
doc["nested"]["k"]     # => "v"

encode({"a": 1, "b": [1, 2]})   # => "a: 1\nb:\n    - 1\n    - 2\n"
```

## Hardening

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

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_depth` | `int` | `64` | Maximum nesting depth when decoding |
| `max_nodes` | `int` | `100000` | Maximum total nodes when decoding |
| `max_input_bytes` | `int` | `5242880` | Maximum input size in bytes (5 MiB) |

Settable via `YAML_MAX_DEPTH` / `YAML_MAX_NODES` / `YAML_MAX_INPUT_BYTES`.
