# Protection coverage

Rampart protects selected parts of a native Windows application rather than
treating "obfuscation" as a single switch. This document describes those
protected surfaces, what is usable today, and where the public roadmap is
headed.

Status terms used here:

- **Ready** means Rampart has a working emitter and behavior-preservation tests.
- **Planned** means the setting is part of the public configuration catalog but
  cannot yet be emitted. Rampart rejects an explicit request for it.
- **Candidate** means a useful direction that is not yet a stable catalog item.

The exact level ceiling for each ready setting is intentional. Presets and bulk
group changes clamp to that ceiling; an explicit unsupported level fails instead
of silently doing less than requested.

## Protected today

| What is protected | Protection | Verified through | What changes |
| --- | --- | --- | --- |
| Build provenance and symbol clues | `packaging.symbol-scrub` | Heavy | Removes debug-directory and PDB-path data, the Rich header, section names, COFF symbol remnants, and build timestamps according to level. |
| PE build identity | `packaging.header-disguise` | Balanced | Replaces genuine timestamp and selected linker metadata with build-seeded decoy values. |
| Imported API surface | `packaging.import-concealment` | Light | Moves eligible imports behind a hash-resolved startup table so the ordinary import view reveals less. |
| Original entry path | `packaging.ep-confusion` | Light | Routes startup through a generated dispatcher which computes and transfers control to the original entry point. |
| Native instruction stream | `code-transformation.junk-insertion` | Maximum | Adds semantics-preserving instruction noise and unreachable decoy branches to verified function regions. |
| Constants in generated runtime code | `code-transformation.mba-constants` | Light | Splits constants in Rampart-generated stubs with per-build arithmetic identities. Target-function constant rewriting is not ready yet. |
| Cross-build binary fingerprints | `code-transformation.per-build-mutation` | Light | Changes generated layout choices, register allocation, keys, and related emitted bytes from the build seed. |
| Embedded ASCII and UTF-16 strings | `strings.encryption` | Balanced | Encrypts eligible referenced string runs in place and restores them during protected startup. |
| String materialization sites | `strings.anti-instrumentation` | Light | Adds sentinels around generated string-decryption work to make simple breakpoint instrumentation less reliable. |
| String-selection scope | `strings.coverage` | Maximum | Controls which referenced strings and sections are eligible, from conservative read-only runs to broad decodable coverage. |

The milestone expansion adds 29 independently selectable Light-level settings:

| What is protected | Protection | What the verified Light emitter does |
| --- | --- | --- |
| Static cross-reference discovery | `analysis.ida-bomb` | Adds 256 bounded cold synthetic functions connected by valid direct-call cross-references. |
| High-level decompilation | `analysis.hexrays-denial` | Adds cold opaque control-flow and relative jump-table decoys without malformed instructions. |
| Symbolic execution | `analysis.symbolic-denial` | Adds bounded cold nonlinear constraint gadgets that do not enter the real execution path. |
| Linear disassembly | `analysis.static-decode-denial` | Adds bounded cold overlapping-decode gadgets for which linear and branch-following interpretations differ. |
| Mapped PE signatures | `analysis.runtime-header-corruption` | Clears mapped MZ and PE signatures after loader initialization, restoring the original page protection afterward. |
| Debugger-presence channels | `anti-debug.channel-sweep` | Cross-checks `IsDebuggerPresent`, `PEB.BeingDebugged`, and `CheckRemoteDebuggerPresent` into shared detection state. |
| Native API prologues | `anti-debug.inline-hook-check` | Captures salted prologue fingerprints and detects common trampoline signatures for selected ntdll exports. |
| VEH availability | `anti-debug.veh-tamper` | Registers a first-priority passive VEH and verifies delivery with a private continuable exception. |
| Loader event visibility | `anti-debug.dll-notify` | Registers an `LdrRegisterDllNotification` callback and records loader-mediated module events. |
| Hypervisor signals | `anti-sandbox.virtualisation-detect` | Records the CPUID hypervisor bit and vendor tuple as evidence without changing application behavior. |
| Analysis-environment artifacts | `anti-sandbox.fingerprint-suite` | Checks exact loaded-module names and environment variables from common sandbox families. |
| Recent user activity | `anti-sandbox.human-gate` | Records whether `GetLastInputInfo` exceeds a conservative 30-minute idle window. |
| Peer process handles | `anti-inject.dacl-hardening` | Applies a process DACL denying new create-thread and VM-write opens while retaining ordinary query access. |
| Hardware return protection | `anti-inject.cet-shadow-stack` | Emits the Windows CET-compatible image characteristic so supported systems can enforce hardware shadow stacks. |
| Executable-memory creation | `anti-inject.dynamic-code-policy` | Applies `ProcessDynamicCodePolicy` during protected startup and records policy rejection. |
| Resolved import targets | `anti-inject.iat-hash-check` | Baselines IAT targets after loader resolution and rechecks them from Rampart's TLS monitor. |
| Dump reconstruction metadata | `memory.anti-dump` | Clears mapped section names, raw sizes/pointers, and obsolete COFF reconstruction fields. |
| Sensitive API call sites | `memory.api-concealment` | Rewrites eligible direct IAT calls and jumps through protector-owned local tail thunks. |
| Mapped section table | `integrity.header-scrub` | Clears every mapped section-table entry after startup while leaving the on-disk PE valid. |
| Runtime sentinels | `integrity.kernel-wall` | Emits build-specific self-hashed sentinel words and records later modifications. |
| Generated code | `integrity.measurement-channels` | Measures relocation-stable generated function ranges with a build-salted runtime hash. |
| TLS callback ownership | `integrity.tls-veh-ownership` | Stores and verifies the final callback-array identity without depending on scrubbed headers. |
| Platform image mitigations | `integrity.mitigation-stack` | Asserts ASLR, high-entropy-VA, and DEP flags while preserving existing CFG metadata. |
| Integrity monitor thread | `integrity.hidden-threads` | Starts a monitor worker, applies `ThreadHideFromDebugger`, and records the PEB debugger signal. |
| Runtime key state | `response.silent-taint` | Idempotently taints protected session-key state when a shared detection flag is raised. |
| Safe detection response | `response.tool-response` | Converts a shared detection flag into a clean process exit; no destructive response is implemented. |
| Build ownership | `response.brand-overlay` | Embeds a bounded build-specific owner/watermark record. |
| Support diagnostics | `response.custom-messages` | Embeds a bounded diagnostic record and emits it to the debugger when detection state is raised. |
| Post-start foreign loads | `nuclear.injection-hunter` | Classifies loader-notified module paths against runtime-captured application and Windows prefixes and records foreign loads. |

Environment probes, mapped-header changes, process-policy changes, response
behavior, and background monitors remain explicit opt-ins rather than preset
defaults. This keeps ordinary Balanced builds conservative while allowing a
release profile to select and compatibility-test each runtime measure.

These protections currently target PE32+ AMD64 executables. DLLs, managed .NET
images, and already-protected inputs are rejected during preflight. Authenticode
signatures do not survive a binary rewrite, so the protected output must be
signed afterward.

### Fine-grained protection boundaries

Rampart can select native function regions from MSVC or GNU linker MAP files,
JSON symbol lists, native PDB public symbols, explicit RVA ranges, and symbol
include/exclude patterns. Ordered rules can match module, section, namespace,
source file, symbol, or RVA range; the last matching rule wins.

Function-level settings currently apply to:

- `packaging.import-concealment`
- `code-transformation.junk-insertion`
- `strings.encryption`
- `strings.anti-instrumentation`
- `strings.coverage`

PE-wide metadata and startup transforms remain global. This prevents a
function rule from pretending it can scope a structure that exists only once in
the image.

### Compatibility surfaces preserved

Protection is only useful when the application still behaves exactly as built.
Preflight inventories and preserves:

- exception/unwind metadata needed by x64 structured exception handling;
- ASLR relocations and declared section/file alignment;
- delay and bound imports;
- load-configuration, CFG, and CET continuation metadata;
- existing TLS callback arrays;
- native executable overlays; and
- the original executable subsystem and machine contract.

Each successful build can also emit a private `.rmap.json` sidecar containing
original/protected RVA mappings, hashes, function identity, and effective
function settings. It is intended for private crash symbolication and build
telemetry, not distribution with the application.

## Remaining roadmap

Nineteen settings remain planned in Rampart's stable catalog. Rampart rejects
explicit requests for these settings until `rampart knobs` reports them ready.

### On-disk image and static code

| Catalog ID | Protected surface | Intended protection |
| --- | --- | --- |
| `packaging.packer` | PE sections and original layout | Compress sections behind a runtime unpacking stage and obscure their original boundaries. |
| `code-transformation.flattening` | Function control-flow graphs | Rebuild verified functions around per-build state dispatch. |

Rampart's scope is defensive transformation. Planned analysis resistance must
remain valid input, must not target vulnerabilities in third-party tools, and
must never damage an analyst's machine or data.

### Injection and process boundaries

| Catalog ID | Protected surface | Intended protection |
| --- | --- | --- |
| `integrity.loader-hijack` | Loader-mediated module admission | Apply an application-owned allow/deny policy to foreign module loads. |

### Memory-resident code and data

| Catalog ID | Protected surface | Intended protection |
| --- | --- | --- |
| `memory.at-rest-encryption` | Dormant heap, TLS, and selected data | Keep opted-in sensitive regions encrypted outside short use windows. |
| `memory.stack-spoof` | Protected call-stack disclosure | Reduce useful application provenance in stack walks without breaking unwinding contracts. |
| `memory.page-mode-decrypt` | Protected executable pages | Expose plaintext only for the page currently executing. |
| `memory.sleep-mask` | Data and code during waits | Re-encrypt opted-in regions while protected threads are dormant. |
| `nuclear.memory-ambush` | Memory-scanning assumptions | Mix bounded decoy regions and rotating indirection into the protected memory map. |

### Virtualized functions

| Catalog ID | Protected surface | Intended protection |
| --- | --- | --- |
| `virtualization.per-build-isa` | VM bytecode format | Generate a distinct opcode, operand, and virtual-register scheme per build. |
| `virtualization.coverage` | Selected native functions | Control which verified functions are lifted to protected bytecode. |
| `virtualization.extended-isa` | Complex native operations | Expand the verified lifter to selected SIMD, string, and atomic instructions. |
| `virtualization.handler-polymorphism` | VM handler fingerprints | Vary handler implementation across builds and call sites. |
| `virtualization.vm-nesting` | Critical virtualized paths | Run selected bytecode through a second, disjoint virtual machine. |
| `virtualization.jit-handlers` | VM handler code at rest | Decrypt handler bodies only for their execution window. |
| `virtualization.runtime-rekey` | Long-running VM bytecode | Move and re-key protected bytecode during execution. |
| `virtualization.decoy-bodies` | Original function locations | Replace lifted bodies with plausible non-executing decoys. |

### Runtime trust and tamper evidence

| Catalog ID | Protected surface | Intended protection |
| --- | --- | --- |
| `integrity.self-debug-port` | Process debug-object ownership | Reserve the debug port for an application-owned monitor in explicitly opted-in builds. |

Runtime signals require conservative policy. Virtual machines, accessibility
software, compatibility layers, hosted desktops, and test automation are legitimate
application environments and must not be treated as proof of tampering by themselves.

### Detection response and build identity

| Catalog ID | Protected surface | Intended protection |
| --- | --- | --- |
| `nuclear.nanomites` | Selected conditional control flow | Resolve opted-in branch decisions through an application-owned exception dispatcher. |
| `nuclear.exception-flow` | Selected control-flow edges | Represent verified transitions through structured exceptions. |

Destructive retaliation, security-tool corruption, persistence, and stealth
intended to bypass endpoint monitoring are explicitly outside Rampart's scope.

## Candidate additions

These additions would close practical gaps for native applications and improve control over
what is protected. They are proposals, not accepted catalog IDs.

### More application assets

- **PE resources:** selectors for resource type, name, and language, with
  encryption for opted-in `RCDATA`, manifests, icons, dialogs, and version data.
- **Shaders:** protection for embedded DXIL, DXBC, and SPIR-V blobs, with an
  allowlist for blobs that must remain inspectable by graphics tooling.
- **Scripts and bytecode:** dedicated handling for embedded Lua, JavaScript,
  Python, and engine-specific bytecode rather than treating them as arbitrary
  strings.
- **Embedded archives and tables:** detection and selective encryption for ZIP,
  pak, SQLite, JSON, and flat data bundled inside the executable or overlay.
- **Secrets and protocol constants:** an opt-in class for license public keys,
  endpoint metadata, matchmaking constants, and anti-cheat configuration, with
  usage-window controls instead of permanent plaintext startup recovery.
- **Resources outside the EXE:** a signed/encrypted asset manifest for adjacent
  DLLs, plug-ins, content packs, and configuration files.

### More precise policy

- Select imports by module and symbol, strings by section/encoding/reference
  owner, resources by type/name, and functions by risk class.
- Allow independent confidentiality, tamper-evidence, and anti-instrumentation
  policies for the same region.
- Add explicit compatibility modes (`preserve`, `warn`, or `fail`) for CFG, CET,
  TLS, unwind data, delay imports, overlays, and signing workflows.
- Add transformation budgets for output growth, startup time, steady-state CPU,
  working set, and worst-case latency.
- Support build profiles such as `developer`, `qa`, `release`, and `tournament`,
  including a deliberate diagnostics policy for crash reporters and profilers.

### Better evidence and CI ergonomics

- Emit a machine-readable coverage report explaining which assets were
  protected, skipped, or rejected and why.
- Compare two builds to show whether a seed changed the intended bytes while
  behavior and public ABI remained stable.
- Add signed configuration manifests and record their digest in the private map
  so a release can be traced to the exact protection policy.
- Provide policy linting for ineffective combinations, excessive performance
  risk, and rules that match no functions or assets.
- Grow the compatibility corpus around real application binaries, plug-in
  loaders, graphics APIs, crash handlers, and applications with large resource
  sections.

## Discovering the live capability set

This file explains coverage, but the CLI is the authority for the current
build. Use:

```powershell
dotnet run --project src/Rampart.Cli -- knobs --ready
dotnet run --project src/Rampart.Cli -- knobs --json
dotnet run --project src/Rampart.Cli -- explain strings.encryption
dotnet run --project src/Rampart.Cli -- check --preset balanced --json
```

Rampart never reports a planned protection as applied. That invariant is more
important than the size of the roadmap.
