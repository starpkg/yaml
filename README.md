# 📄 `yaml` — YAML for Starlark

[![Go Reference](https://pkg.go.dev/badge/github.com/starpkg/yaml.svg)](https://pkg.go.dev/github.com/starpkg/yaml)
[![license](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![codecov](https://codecov.io/gh/starpkg/yaml/graph/badge.svg)](https://codecov.io/gh/starpkg/yaml)
![binary footprint](https://img.shields.io/badge/binary_footprint-%2B0.6_MB-blue)

Decode and encode [YAML](https://yaml.org/) from Starlark, built on
[gopkg.in/yaml.v3](https://gopkg.in/yaml.v3).

Decoding is **hardened**: input size, nesting depth, and total node count are
bounded; parse panics become errors; and YAML's bare-timestamp footgun is tamed.

> **Where this fits.** `starpkg` is support for necessary **local** operations
> plus simple abstractions over common **online** services, for ease of use.
> `yaml` is a **local** capability — a pure in-process text↔value codec with no
> network, filesystem, or external service involved.

For the complete per-builtin reference — signatures, parameters, returns,
errors, examples — and the configuration accessors, see
**[docs/API.md](docs/API.md)**.

## Installation

```bash
go get github.com/starpkg/yaml
```

## Quickstart

The host constructs a `Module` and hands its `LoadModule()` loader to a Starlet
machine; the script reaches it through `load("yaml", …)`:

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
print(decode("a: 1")["a"])     # => 1
print(encode({"b": [1, 2]}))   # => "b:\n    - 1\n    - 2\n"
`), nil)
}
```

`NewModule()` reads the caps (`max_depth` / `max_nodes` / `max_input_bytes` /
`max_time` / `max_encode_depth`) from defaults or the `YAML_*` environment
variables. `ModuleName` is the constant `"yaml"`.

## Starlark API at a glance

Top-level builtins (`load("yaml", …)`):

- `decode(text)` — parse a YAML document (string or bytes) into Starlark values.
- `encode(value)` — serialize a Starlark value to a YAML string.

There are no object methods: `decode` returns plain Starlark containers/scalars
(`dict` / `list` / `str` / `int` / `float` / `bool` / `None`), and `encode`
returns a `str`. Bare timestamps decode to RFC 3339 strings; anchors, aliases,
and merge keys (`<<`) resolve through `decode`.

See **[docs/API.md](docs/API.md)** for the full signatures, return values,
errors, hardening notes, and examples of both builtins.

## Configuration

The decode caps (`max_depth`, `max_nodes`, `max_input_bytes`) plus two
**host-only** DoS levers — `max_time` (a per-decode wall-clock bound;
`max_input_bytes` bounds size but not yaml.v3's super-linear *parse* time, and a
merge-key chain under the byte cap can be O(n²)) and `max_encode_depth` (the
encode stack-safety fence — a value nested too deep would overflow the Go stack
in `dataconv`/yaml.v3, so it's rejected first) — are configured via environment
variables (`YAML_*`) or the accessor builtins. The host-only levers have no
`set_*` (a script cannot disable them). See the
[Configuration section of docs/API.md](docs/API.md#configuration) for the full
option table, defaults, and accessors.

## License

MIT
