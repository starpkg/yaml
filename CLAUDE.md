# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`starpkg/yaml` is an **L4 domain module** of the Star\* ecosystem: it exposes YAML decoding and encoding to Starlark scripts. A script loads the module and converts between YAML text and Starlark values (`dict`/`list`/`str`/`int`/`float`/`bool`/`None`).

Positioning: **`starpkg` is support for necessary local operations plus simple abstractions over common online services, for ease of use.** `yaml` sits squarely on the **local** side — a pure in-process text↔value codec. There is no network, no filesystem, no external service; the only thing the host configures is how much work a decode is allowed to do.

It is pure Go, all platforms, built on `gopkg.in/yaml.v3`. Layer position: depends downward on `starpkg/base` (the module/config system), `1set/starlet` (the Machine + `dataconv` value bridge), and transitively `1set/starlight` + `go.starlark.net`. Nothing in the ecosystem depends on it.

## Dev commands

Pure Go library with a Makefile. From this repo:

```bash
make test                                  # -race -cover, the working bar
make ci                                    # -race -cover profile + bench compile (what CI runs)
go test ./... -run TestAnchorsAliasesMerge # a single test
gofmt -l . && go vet ./...                 # must be clean before commit
```

**Verify on the go floor in Docker** — this repo's floor is **go 1.19** (see Release discipline), and behavior on the floor must be checked in a container because the local toolchain is newer:

```bash
docker run --rm -v "$PWD":/src -v "$HOME/go/pkg/mod":/go/pkg/mod -w /src golang:1.19 go test -race -count=1 ./...
```

Integration scripts under `../test/yaml/*.star` would live in the **private `starpkg/test` repo** and auto-skip when that directory is absent (e.g. in CI); this module currently keeps its coverage in `yaml_test.go` (see Test organization).

## Architecture (the part that spans files)

The module is a thin, **single-file** bidirectional codec: `decode` parses YAML text into Starlark values; `encode` lowers a Starlark value to Go and marshals it back to YAML text. Everything lives in `yaml.go`.

- **`yaml.go`** — the whole module.
  - **`Module`** holds a `base.ConfigurableModule` (`cfgMod`) and its `Extend()` accessor (`ext`). `NewModule()` registers three int config options — `max_depth`, `max_nodes`, `max_input_bytes` — each with a `YAML_*` env var (built by `genConfigOption`, a generic helper over `base.NewConfigOption`).
  - **`LoadModule()`** registers exactly two script-facing builtins via `base.ConfigurableModule.LoadModule`: **`decode`** and **`encode`**. There are no object methods — `decode` returns plain Starlark containers/scalars, `encode` returns a `str`.
  - **`decode`** (`m.decode`) unpacks a `text` arg (`types.StringOrBytes`), enforces `max_input_bytes` against the raw input length, calls `unmarshal`, then walks the result through `toStarlark` with a fresh node counter.
  - **`encode`** (`m.encode`) unpacks a `value` arg, lowers it to a Go value with `dataconv.Unmarshal`, then calls `marshal`.
  - **`unmarshal` / `marshal`** wrap `goyaml.Unmarshal` / `goyaml.Marshal` with a deferred `recover()` so a parser/encoder panic becomes a script-level error.
  - **`toStarlark`** is the conversion core: a type switch over the decoded `interface{}` (`nil`/`bool`/`int`/`int64`/`uint64`/`float64`/`string`/`time.Time`/`[]interface{}`/`map[string]interface{}`/`map[interface{}]interface{}`) that recurses while threading `depth` and a `*nodes` counter and enforcing `maxDepth`/`maxNodes`. The default arm rejects any unhandled Go type as a `"unsupported value of type"` error.
  - **`upper`** is a small ASCII upper-caser used only to derive env-var names.

Third-party wrap points: `gopkg.in/yaml.v3` (parse/marshal, behind `unmarshal`/`marshal`) and Starlet's `dataconv.Unmarshal` (the Starlark→Go lowering used by `encode`). The Go→Starlark direction is hand-written in `toStarlark` rather than delegated, because that is where the hardening lives.

## Invariants / hardening (preserve when editing)

The decode path treats input as untrusted. Keep these properties; they are the reason `toStarlark` is hand-written instead of a generic conversion.

1. **No host panics from script input.** `unmarshal` and `marshal` each `defer`/`recover()` into an error — a malformed document or an unmarshalable value becomes a script error, never a host crash. Don't remove the deferred recovers.
2. **Bounded decode (capwalk).** Three caps fence the work a decode can do: `max_input_bytes` (checked on the raw text before parsing), and `max_depth` + `max_nodes` (enforced as `toStarlark` recurses, via the `depth` argument and the shared `*nodes` counter). New recursion in `toStarlark` must keep incrementing `*nodes` and checking both caps. Defaults: depth `64`, nodes `100000`, bytes `5 MiB`.
2b. **Bounded parse time + encode depth (PKG-27).** `max_nodes` is a *post-parse* fence — it can't bound yaml.v3's super-linear *parse* time (a merge-key chain well under the byte cap parses in ~O(n²)). `decode` runs `unmarshal` through `unmarshalBounded`, a goroutine + wall-clock deadline (thread context via `base/util.OpContext` plus the **host-only** `max_time`, default `0`); on timeout it returns `errDecodeTimeout`. The input is an immutable `[]byte`, so nothing is shared with an abandoned goroutine (unlike liquid's bindings). **Encode** is fenced by `checkStarlarkDepth`, which rejects a value nested deeper than the **host-only** `max_encode_depth` (default `10000`) **before** `dataconv.Unmarshal` — both that lowering *and* yaml.v3's `Marshal` recurse over the value, so an over-deep value would drive a fatal, uncatchable stack overflow in one of them; a time bound can't prevent that. Three properties make the fence safe and complete. (a) It uses a **separate host-only** limit, **not** the script-settable `max_depth` — otherwise a script could `set_max_depth(0)` to disable the overflow protection, and `max_depth=64` would reject a legitimate 65-deep encode; the default is generous (real values nest <100 deep) yet far below the ~millions-deep recursion that exhausts the Go stack, and a non-positive configured value falls back to the default (never disable-able). (b) It **mirrors dataconv.Unmarshal's recursion set** — leaf scalars (checked first, so a `String`'s own attribute methods don't make it look like a container), then `IterableMapping` (dict/GoMap), `Iterable` (list/tuple/set/GoSlice), and `HasAttrs` (`starlarkstruct.Struct`/`Module`, the kind that is neither iterable nor a mapping yet dataconv recurses into via `AttrNames` — the codex-found bypass). (c) It **bails at `maxDepth+1`**, so the check's own recursion is bounded by the limit and cannot itself overflow while measuring a million-deep value. Keep `encode` calling `checkStarlarkDepth` **before** `dataconv.Unmarshal` (not on the Go value afterwards — dataconv would overflow first), and keep the scalar arm first. Host-wrapped values are covered too: starlight's `convert.GoMap` implements `IterableMapping`, `GoSlice` implements `Iterable`, and `GoStruct`/`GoInterface` implement `HasAttrs`, and their nested values are re-wrapped, so the walk descends into them and measures their true depth (a wrapped type that *hid* its nesting from the `starlark.Value` interface would be a residual, but the standard wrappers don't). Known limitation: on decode timeout the abandoned goroutine runs until yaml.v3 finishes — a hard CPU bound needs an OS/sandbox limit.
3. **Bare timestamps are strings.** `yaml.v3` will turn a bare scalar like `2020-01-02` into a Go `time.Time`. The `time.Time` arm of `toStarlark` formats it as an RFC 3339 **string**, so `type(doc["date"]) == "string"` always holds — never surface an opaque value. Keep this arm.
4. **Deterministic order.** Both map arms sort keys before materializing the `dict` (string keys via `sort.Strings`; non-string keys are stringified with `fmt.Sprintf("%v", k)` then sorted). `encode` inherits `yaml.v3`'s sorted-key output. Don't materialize a Go map in native (random) order.
5. **Alias/anchor expansion.** A "billion laughs" alias bomb is rejected as a decode error by `yaml.v3`'s own guard; the capwalk caps are an additional backstop on the materialized result. Both are tested (`TestAliasBombRejected`).
6. **Backward compatibility (iron rule).** The caps are the only host levers and they default to generous values, so existing scripts decode/encode identically. Any new safety lever must default to the historical behavior.

## Test organization

Group by functional goal — **do not add one `*_test.go` per fix.** `yaml_test.go` is the single home, opened with a commented section list: decode/encode round-trip, bare-timestamp taming, capwalk limits (depth/nodes/input bytes), defensive/error arms (unsupported `toStarlark` type, encode failure), and anchors/aliases/merge keys. Add a new test as a **section here**, not a new file. Tests are table/script-driven through the `run` helper (a Starlet machine with the module lazy-loaded); no third-party test framework. Keep functions small (Codacy's `nloc` rule). When `../test/yaml/*.star` integration scripts exist in the private `starpkg/test` repo, they must auto-skip when that directory is absent.

## Documentation

Three layers must stay in sync (enforced by the doc standard, `plan/starpkg文档标准（DOC-STD）`):

- **`README.md`** — every script-facing builtin (`decode`, `encode`) documented as a backtick whole-word, with signature/args/return/behaviour matching the code; the decode caps documented under *Configuration*. The doc-coverage gate (`doccov`) fails CI if a registered builtin is undocumented.
- **GoDoc** — package comment + a doc comment whose first word is the symbol name on every exported symbol (`ModuleName`, `Module`, `NewModule`, `LoadModule`); gated by `revive`'s `exported` rule in CI.
- **`CLAUDE.md`** — this file.

## Release discipline

- **Floor = go 1.19**, following this repo's `go.mod`; the floor only rises in its own dedicated pin PR. The `go.starlark.net` baseline is the ecosystem pin (`ffb3f39`).
- **CI** runs through the centralized reusable workflow in `1set/meta` (`.github/workflows/build.yml` references it by commit SHA), with `go-floor: "1.19"` and the doc-coverage gate enabled.
- **Pin upgrade is the last PR of the series**: bump `go.starlark.net` + the `1set/*` deps + the go floor as one isolated PR, after all fixes; never tag before it merges.
- **Bumping the version, the go floor, or tagging are user-confirmed actions** — never tag autonomously; default to patch bumps; published tags are immutable in the module proxy.
