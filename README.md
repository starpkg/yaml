# 📄 `yaml` — YAML for Starlark

[![Go Reference](https://pkg.go.dev/badge/github.com/starpkg/yaml.svg)](https://pkg.go.dev/github.com/starpkg/yaml)
[![license](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![codecov](https://codecov.io/gh/starpkg/yaml/graph/badge.svg)](https://codecov.io/gh/starpkg/yaml)
![binary footprint](https://img.shields.io/badge/binary_footprint-%2B0.4_MB-blue)

Decode and encode [YAML](https://yaml.org/) from Starlark, built on
[gopkg.in/yaml.v3](https://gopkg.in/yaml.v3).

Decoding is **hardened**: input size, nesting depth, and total node count are
bounded; parse panics become errors; and YAML's bare-timestamp footgun is tamed.

> **Where this fits.** `starpkg` is support for necessary **local** operations
> plus simple abstractions over common **online** services, for ease of use.
> `yaml` is a **local** capability — a pure in-process text↔value codec with no
> network, filesystem, or external service involved.

## Installation

```bash
go get github.com/starpkg/yaml
```

## Wiring the module

The host constructs a `Module` and hands its `LoadModule()` loader to a Starlet
machine; the script reaches it through `load("yaml", ...)`.

```go
package main

import (
    "github.com/1set/starlet"
    "github.com/starpkg/yaml"
)

func main() {
    m := yaml.NewModule()
    interp := starlet.NewWithLoaders(nil, nil, starlet.ModuleLoaderMap{
        yaml.ModuleName: m.LoadModule(),
    })
    _, _ = interp.RunScript([]byte(`
load("yaml", "decode", "encode")
print(decode("a: 1")["a"])
`), nil)
}
```

`NewModule()` reads the decode caps (`max_depth` / `max_nodes` /
`max_input_bytes`) from defaults or the `YAML_*` environment variables — see
[Configuration](#configuration). `ModuleName` is the constant `"yaml"`.

## Functions

The module exposes two script-facing builtins. There are no object methods:
`decode` returns plain Starlark values (`dict` / `list` / `str` / `int` /
`float` / `bool` / `None`) and `encode` returns a `str`.

| Function | Signature | Description |
|----------|-----------|-------------|
| `decode` | `decode(text) -> value` | Parse a YAML document into Starlark values. |
| `encode` | `encode(value) -> str` | Serialize a Starlark value to YAML text. |

### `decode(text)`

Parses a YAML document and returns Starlark values. `text` may be a `str` or
`bytes`. A YAML mapping becomes a `dict` (string keys; non-string keys are
stringified), a sequence becomes a `list`, and scalars become `None` / `bool` /
`int` / `float` / `str`. A scalar that YAML would parse as a date or datetime is
returned as an RFC 3339 `str` (see [Hardening](#hardening)). Anchors, aliases,
and merge keys (`<<`) are resolved by the parser. Raises an error when the input
exceeds a cap, the document is malformed, or it decodes to an unsupported type.

### `encode(value)`

Serializes a Starlark `value` to a YAML `str`. The value is first lowered to a
Go value (via Starlet's `dataconv.Unmarshal`), then marshalled with
`gopkg.in/yaml.v3`. Mapping keys are emitted in sorted order. Raises an error if
the value cannot be lowered (e.g. a self-referential/cyclic container) or
marshalled.

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

### Anchors, aliases, and merge keys

YAML's cross-reference features resolve through `decode` — an alias reuses an
anchored value, and a merge key (`<<`) inherits an anchored mapping while
allowing per-key overrides:

```python
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
