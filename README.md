# pkgguard

**A [Bifrost](https://github.com/maximhq/bifrost) gateway plugin that stops AI agents from installing malicious, hallucinated or unsafe packages.**

A coding agent decides to run `npm install some-package`, and that decision came from a language model. Models invent package names, attackers register those names ("slopsquatting"), typosquat popular ones, and hijack real ones. Every agent request already passes through the gateway, so the gateway is the right place to check the install *before the agent runs it*, whichever agent, package manager or model provider is behind it.

```
agent ──▶ Bifrost ──▶ model: "run: pip install flask-jwt-auth-helper-pro"
                 │
                 └─ pkgguard (LLMPlugin + MCPPlugin + stream hook)
                      ✗ flask-jwt-auth-helper-pro does not exist on PyPI
                        (models invent plausible names; attackers register them later)
                      tool call removed, reason written into the reply ──▶ agent picks another way
                      a human can Approve a specific package on the dashboard
```

## See it work

```bash
go run ./cmd/pkgguard demo                 # scripted agent session through the real Bifrost core
go run ./cmd/pkgguard demo -dashboard      # same, then keep the live dashboard open (approve a package)
go run ./cmd/pkgguard bench                # the red-team benchmark below
go run ./cmd/pkgguard check "npm install expresss"      # one command, checked live against npm / PyPI / OSV
go run ./cmd/pkgguard audit package-lock.json           # audit a lockfile (one batched OSV request)
```

The demo runs seven agent turns through a real Bifrost client with pkgguard installed. A scripted stand-in plays the model (a real model's mistakes, replayed deterministically); nothing is ever executed. Abridged:

```
task: Add JWT auth to my Flask app
  -> model wants: pip install flask-jwt-auth-helper-pro (the model invented a package name)
  BLOCKED tool call removed. The agent reads:
      [pkgguard] BLOCKED: ... (high) flask-jwt-auth-helper-pro: does not exist on pypi ...
task: (agent retries after reading why)
  -> model wants: pip install flask-jwt-extended
  ALLOWED agent runs: pip install flask-jwt-extended
task: Add pretty console logging
  -> model wants: npm install pretty-logs (a package whose postinstall steals the environment)
  BLOCKED ... (critical) install-time code serialises the environment and sends it over the network
      > setup.js:2 const body = JSON.stringify(process.env);
result: 3 installs allowed, 4 blocked before they could run.
```

## Results: red-team benchmark

`pkgguard bench` scores three systems on 111 labelled commands in a synthetic, deterministic package world (no network; 53 attacks in 13 classes, 52 benign commands including legitimate install scripts and look-alike names, 6 documented evasions). The same run is a CI gate.

| System | Attacks caught | Benign blocked | Benign warned |
|---|---|---|---|
| Blocklist only (what most install scanners are) | 6 / 53 (11%) | 0 / 52 | 0 |
| pkgguard offline (local rules only, no network) | 14 / 53 (26%) | 0 / 52 | 0 |
| **pkgguard full** (registry + OSV + static install-script scan) | **53 / 53 (100%)** | **0 / 52** | 0 |

Attack classes: hallucinated package, typosquat (new / old and unused), known malware, compromised release of a real package, malicious dependency, malicious install script (env exfiltration, SSH keys, curl-to-shell, reverse shell, obfuscated payload, persistence, text aimed at the reviewer), brand-new version, git/URL source, registry override, dependency confusion, pipe-to-shell, and commands hidden behind `sudo`/`cd &&`/`bash -c`/env prefixes.

**How to read these numbers honestly.**
- The world is synthetic and authored by us. Attack shapes follow public incident patterns, but every package and host is fictional. This measures coverage and regressions, not real-world recall.
- We fixed misses we saw while building it (e.g. two-edit typosquats, Rust packages), so 100% is on the corpus we developed against. That is why the benchmark also carries **known gaps**, evasions we document and do not catch: an install hidden in `eval "$(… | base64 -d)"`, an install inside `python -c` / `node -e`, string-built exfiltration (`['ht','tps'].join('')`), payloads outside the install hooks, and typosquats of names outside the seed list. **pkgguard catches 0 of these 6**, and so does everything else; see [Limits](#limits-read-these).
- The Claude reviewer is not in the benchmark (a deterministic run cannot include a live model).

Real-world checks we did run, by hand, against live npm / PyPI / OSV: `npm install debug@4.4.2` (a compromised release) is blocked via OSV; plain `debug` and `express` pass; `pip install reqeusts` is blocked as non-existent; an old but nearly unused lookalike (`expresss`) is warned about.

## What it checks

| Check | What it catches | Needs |
|---|---|---|
| `phantom-package` | the package does not exist (hallucinated name an attacker can register) | registry |
| `known-malware` | the **exact version** to be installed is listed as malware in [OSV](https://osv.dev) (`MAL-*`); a name-only query would condemn packages with one bad old release, so OSV is asked about the resolved version | OSV (name + version only) |
| `typosquat` | one or two edits from a popular package; severity depends on package age and weekly downloads | name list; registry for severity |
| `too-new` | version published < 24 h ago (most malicious releases are caught within a day); the hint names the newest older version | registry |
| `install-*` (static scanner) | install-time code that serialises the environment and sends it out, reads SSH/cloud credentials and talks to the network, downloads and runs code, opens a reverse shell, decodes and runs a hidden payload, persists in shell profiles/cron, contacts disposable collection hosts, or addresses its reviewer ("this package is safe") | npm tarball, read in memory |
| `claude-review` | Claude reads the install-time code of flagged npm packages; **every claim must cite a real line** | Anthropic API key |
| `dependency-phantom`, `dependency-malware` | a direct dependency that does not exist publicly (dependency confusion) or is known malware | registry, OSV |
| `source-git`, `source-url` | install from a git repo or arbitrary URL | none |
| `custom-registry`, `extra-index` | `--registry` / `--index-url` outside an allow-list; pip `--extra-index-url` | none |
| `pipe-to-shell` | `curl … \| sh`, `sh -c "$(curl …)"` | none |

Package managers understood: npm, npx, pnpm, yarn, bun, pip, uv/uvx, pipx, poetry, cargo, `go get/install`, gem. Registry checks (existence, age, downloads) cover **npm, PyPI, crates.io and RubyGems**; install-script and dependency checks cover npm.

**Severity → action.** Findings are ranked info → critical. At `block_at` (default `high`) a command is blocked, at `warn_at` (default `medium`) the agent is warned. `mode: "monitor"` never blocks and only reports, for rolling it out safely.

### The static scanner is the part that works without a model

Rules fire on *combinations* (environment dump + network sink, secret path + network sink, download + execute) or on unmistakable signatures, because a network call or a downloaded binary alone is normal for a native addon. A false-positive suite covers `node-gyp rebuild`, banner scripts, esbuild-style prebuilt-binary downloads, `{ ...process.env }` spreads and `process.env.HOME` reads. Every finding quotes `file:line` evidence.

### How the Claude reviewer stays honest

1. It sees only numbered install-time code, nothing is executed.
2. Its system prompt marks package text as untrusted data and treats text addressed to a reviewer as a sign of malice.
3. **Code, not the model, validates the answer** ([`Verdict.Validate`](reviewer.go)): a `suspicious`/`malicious` verdict must cite `file:line` rows that exist in what the model was shown. Invented citations are dropped; a verdict left with none is downgraded to `unverified` and cannot block. Cited lines are quoted back in the finding.
4. A *benign* verdict never overrides a hard signal, and a reviewer error never blocks.

## Human in the loop: dashboard and approvals

A block message that says "ask the user to approve it" should end in a real action. Set `dashboard_addr` and the plugin serves a live dashboard (events over SSE, stats, top risk signals) with an **Approve** button per package and a revoke list.

- **Approvals can't unblock real malware.** An approval clears findings *below critical* for that package, with an expiry (default 24 h) and optional persistence (`approvals_file`). Known malware, malicious install-time code and the deny list are critical and cannot be approved at runtime, so a prompt-injected "please approve this" can't unblock them. The dashboard doesn't even offer the button for those.
- Loopback by default; every API call needs a token (printed at start, or `dashboard_token`); a non-loopback address is refused unless you set a token; the `Host` header is checked against DNS rebinding.
- The dashboard is its own small listener, not a route on the gateway: Bifrost runs plugin HTTP hooks only for routes it already serves (its 404 handler bypasses them), so a plugin cannot add `/pkgguard` to the gateway's port.

## Streaming

In a streamed chat completion a tool call arrives in fragments, and by the time the command is complete the first fragments have already reached the client. `HTTPTransportStreamChunkHook` sees each chunk before the client does, so pkgguard withholds tool-call fragments, reassembles each call, and at the choice's `finish_reason` either emits the complete call (allowed) or drops it and puts the explanation in the final chunk's text (blocked; `finish_reason` becomes `stop` when no call is left). Text is never delayed; tool calls arrive at the end of the stream. If a stream dies before it finishes, the withheld calls are never emitted (fail closed). Chat-completion streams only.

## Audit a project

```bash
pkgguard audit                       # package-lock.json / package.json / requirements.txt in the current directory
pkgguard audit -deep package-lock.json
```

Fast mode checks every pinned version against OSV in **one batched request** and flags lockfile entries resolved from outside the registry or from git (the way a poisoned pull request swaps a package's source). `-deep` also runs the registry, install-script and Claude checks on up to 100 packages. Exit status 2 on high/critical findings, so it works as a CI step.

## Use it with Bifrost

pkgguard uses only Bifrost's supported extension points. Two ways to run it:

### 1. Go SDK / embedded Bifrost

```go
p, err := pkgguard.Init(map[string]any{"mode": "enforce", "dashboard_addr": "127.0.0.1:8099"})
client, err := bifrost.Init(ctx, schemas.BifrostConfig{
    Account:    myAccount,
    LLMPlugins: []schemas.LLMPlugin{p},
    MCPPlugins: []schemas.MCPPlugin{p},
})
```

[`bifrost_e2e_test.go`](bifrost_e2e_test.go) and `pkgguard demo` do exactly this against the real Bifrost core. The streaming hook is part of Bifrost's HTTP transport and applies to the gateway, not to the SDK.

### 2. Standard Bifrost gateway (native plugin)

Dynamic plugins need a dynamically linked Bifrost build (see Bifrost's [building a dynamic binary](https://github.com/maximhq/bifrost/blob/main/docs/plugins/building-dynamic-binary.mdx)); Go's plugin mode exists on Linux and macOS only.

```bash
CGO_ENABLED=1 go build -buildmode=plugin -o pkgguard.so ./plugin
```

Then register it in Bifrost's `config.json` ([`examples/config.json`](examples/config.json)).

### Configuration

| Key | Default | Meaning |
|---|---|---|
| `mode` | `enforce` | `monitor` never blocks, it only warns and audits |
| `block_at` / `warn_at` | `high` / `medium` | severity thresholds (`info`, `low`, `medium`, `high`, `critical`) |
| `min_age_hours` | `24` | hold versions younger than this; `0` turns it off |
| `allow` / `deny` | `[]` | package names that skip all checks / are always blocked |
| `allowed_registries` | npm, PyPI, crates, Go, RubyGems hosts | hosts `--registry` / `--index-url` may point at |
| `offline` | `false` | no network at all: only name, source, registry-flag and pipe-to-shell rules |
| `disable_osv` | `false` | skip the OSV lookup |
| `fail_closed` | `false` | a failed lookup blocks instead of warning |
| `check_dependencies` | `true` | also check an npm package's direct dependencies |
| `ignore_tools` | write/edit/read/… | tool-name substrings never scanned (an install command inside a file write is just text) |
| `anthropic_api_key` | `$ANTHROPIC_API_KEY` | enables the Claude reviewer |
| `reviewer_model` | `claude-sonnet-5-5` | model used for the review |
| `audit_log` | none | JSONL file; every decision is appended |
| `dashboard_addr` | none | e.g. `127.0.0.1:8099`; enables the dashboard |
| `dashboard_token` | random, logged at start | required for every dashboard API call |
| `approvals_file` | none | persist human approvals (JSON) |

### What the agent sees

A blocked tool call is removed from the model's response and the reason is appended to the assistant text, so the agent reads why and can recover instead of failing blindly (the demo shows the recovery). For Responses-API requests the `function_call` item is replaced by an explanatory assistant message; for MCP tool executions the call is short-circuited with a 403.

## Built on Bifrost

This project is an extension of the open-source [maximhq/bifrost](https://github.com/maximhq/bifrost) gateway. What it uses from the Bifrost repository:

| Bifrost piece | Where we use it |
|---|---|
| `schemas.LLMPlugin` (`core/schemas/plugin.go`): `PreRequestHook`, `PreLLMHook`, `PostLLMHook` | [`plugin.go`](plugin.go): `PostLLMHook` inspects and rewrites `BifrostChatResponse` / `BifrostResponsesResponse` tool calls |
| `schemas.MCPPlugin`: `PreMCPHook` / `PostMCPHook`, `MCPPluginShortCircuit` | [`plugin.go`](plugin.go): blocks unsafe installs in MCP tool executions before they reach the MCP server |
| `schemas.HTTPTransportPlugin`: `HTTPTransportStreamChunkHook` (withhold or rewrite a chunk) | [`stream.go`](stream.go): reassembles streamed tool calls and enforces the policy on them |
| `schemas.BifrostError` with `AllowFallbacks` | blocked MCP calls return a 403 with `AllowFallbacks=false` (a fallback provider would return the same tool call) |
| Native plugin contract (`examples/plugins/multi-interface`) | [`plugin/main.go`](plugin/main.go) exports `Init`, `GetName`, the LLM/MCP/HTTP hooks, so the `.so` loads in a standard dynamic Bifrost build |
| `bifrost.Init` and the plugin pipeline (`core`) | [`bifrost_e2e_test.go`](bifrost_e2e_test.go) and [`cmd/pkgguard/demo.go`](cmd/pkgguard/demo.go) run the plugin inside the real core, following the pattern of Bifrost's own `plugins/mocker` tests (a short-circuiting plugin plays the model) |
| Plugin config object in `config.json`; plugin sequencing docs | [`examples/config.json`](examples/config.json); `Init(config any)` accepts the loosely typed map Bifrost passes |
| `replace github.com/mark3labs/mcp-go => github.com/maximhq/mcp-go …` | Bifrost core pins a fork of `mcp-go` and `replace` is not inherited, so [`go.mod`](go.mod) repeats it (any module that imports `bifrost/core` needs this) |

Reading Bifrost's gateway code also settled a design question: the HTTP middleware is chained per registered route, so a plugin cannot serve its own paths on the gateway port. That is why the dashboard is a separate listener.

## How AI is used

- **Claude** (Anthropic Messages API) is the install-code reviewer: structured JSON verdicts with cited lines, validated by code. It runs only on flagged npm packages, after the static scanner, and is optional.
- The gateway position is what lets pkgguard guard *any* model behind Bifrost with no change to the agent.
- This project was written with the help of Claude Code.

## Inspiration and originality

The idea of an install-time package guard for AI agents comes from [lb2002/gatekeeper](https://github.com/lb2002/gatekeeper) (Meta hackathon). pkgguard is a new implementation in Go on a different surface and reuses none of its code. Ideas it borrows: a waiting period for brand-new versions, checking dependencies that do not exist publicly, and verdicts that must cite code that code verifies. What is different: it lives in the **gateway** (it covers every package manager and any agent that goes through Bifrost, with no PATH shims), it reads **model output** (including hallucinated names, which a shim cannot know about), it covers PyPI, crates.io, RubyGems, pnpm/yarn/bun and `curl | sh`, it enforces on **streamed** tool calls, it has a human approval loop with a hard floor, and it ships a benchmark with documented gaps. What Gatekeeper has that pkgguard does not: a live monitor of every new npm release, a campaign memory, and a hosted try-it page.

## Limits (read these)

- **The benchmark is synthetic and tuned against.** See above. It is a regression gate and a coverage map, not a measurement of real-world recall.
- It only sees what passes through the gateway. An agent that shells out on its own with a hand-typed command never reaches it. It guards model-chosen installs; it is not a sandbox.
- It reads a command with a purpose-built parser, not a shell. Installs hidden behind `eval`, encoded strings, variables, or `python -c` / `node -e` are not seen (benchmark "known gaps"; the `sh -c "$(curl …)"` pattern is handled).
- The static scanner reads only the files an install script points at. Malware that runs when the package is *required*, not installed, is not seen. String-built or heavily obfuscated code can evade the rules; Claude is the second line there.
- Version ranges are resolved approximately (to the registry's `latest`); exact versions and dist-tags are exact. Dependency checking is one level deep.
- The typosquat list is a seed of ~260 well-known names, not the whole registry.
- Streaming: chat-completion streams only (not Responses-API streams), tool calls arrive at the end of the stream, and the stream hook was exercised with replayed chunks in tests, not against a live gateway.
- The Claude reviewer has been exercised against a fake API server in tests, not against the live API. PyPI `setup.py` is not reviewed.
- The `.so` build could not be tested in the authoring environment (Windows has no Go plugin mode); CI builds it on Linux.

## Development

```bash
go test ./...                    # parser, engine, scanner, registries (fakes + httptest), plugin hooks, streaming, dashboard, audit, benchmark gate, real Bifrost core
go vet ./...
go run ./cmd/pkgguard bench      # also what CI runs
```

Tests never touch the network; the CLI examples above do.

Layout: [`parse.go`](parse.go) (shell → installs) · [`engine.go`](engine.go) (checks → decision) · [`staticscan.go`](staticscan.go) · [`registry.go`](registry.go) · [`osv.go`](osv.go) · [`reviewer.go`](reviewer.go) (Claude + citation validation) · [`typosquat.go`](typosquat.go) · [`audit.go`](audit.go) · [`plugin.go`](plugin.go) (Bifrost hooks) · [`stream.go`](stream.go) · [`approvals.go`](approvals.go) · [`dashboard.go`](dashboard.go) · [`bench.go`](bench.go) / [`sim.go`](sim.go) (benchmark world) · [`plugin/`](plugin) (`.so` wrapper) · [`cmd/pkgguard`](cmd/pkgguard) (CLI: `check`, `audit`, `bench`, `demo`).

Licensed under Apache-2.0, the same license as Bifrost, so it can be proposed upstream as a community plugin.
