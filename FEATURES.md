# Protection coverage

This guide describes Rampart's supported protections, target-specific limits,
and compatibility requirements for native Windows x64 executables, pure managed
IL assemblies, and eligible Windows x64 NativeAOT outputs.

Presets and bulk group changes are limited to supported levels. An explicit
request for an unsupported level fails validation. A supported setting may still
skip an input region that does not meet its requirements; review the build log
and applied-protection report for each output.

## Native PE protection

| What is protected | Protection | Verified through | What changes |
| --- | --- | --- | --- |
| Build provenance and symbol clues | `packaging.symbol-scrub` | Maximum | Removes debug/PDB payloads, including file-only payloads, plus Rich data, section names, references, and timestamps by level. Maximum clears validated file-only COFF symbol/string tables while preserving adjacent assets; mapped or malformed COFF payloads are rejected. |
| PE build identity | `packaging.header-disguise` | Maximum | Heavy adds a consistent linker/image-version profile and export/debug timestamps while preserving loader compatibility and import-binding fields. Maximum computes the checksum over final file bytes. |
| Imported call references | `packaging.import-concealment` | Light | Routes eligible references through seeded export-name hash lookup with exact collision verification and Windows-managed final binding. Original loader import names and bindings remain intact. |
| Original entry path | `packaging.ep-confusion` | Light | Routes startup through a generated dispatcher which computes and transfers control to the original entry point. |
| Native instruction stream | `code-transformation.junk-insertion` | Maximum | Light fills verified padding; higher levels additionally rewrite explicitly selected, verified register-only leaf bodies with increasing in-body noise density. Heavy/Maximum include bounded dead branches. Padding alone reports Light. |
| Constants in generated/runtime and selected native code | `code-transformation.mba-constants` | Maximum | Balanced reconstructs eligible target immediates through modular arithmetic/XOR. Heavy nests two layers; Maximum varies three or four layers with arithmetic/XOR/rotation identities. All levels preserve live flags; stub-only work reports Light. |
| Cross-build binary fingerprints | `code-transformation.per-build-mutation` | Light | Changes generated layout choices, register allocation, keys, and related emitted bytes from the build seed. |
| Embedded ASCII and UTF-16 strings | `strings.encryption` | Balanced | Encrypts eligible referenced string runs in place and restores them during protected startup. |
| String materialization sites | `strings.anti-instrumentation` | Light | Checks the decryptor instruction range and record table before use; detected modifications leave the affected strings encrypted and record a shared detection flag. |
| String-selection scope | `strings.coverage` | Maximum | Selects referenced ASCII/UTF-16LE strings with six/eight/three-character floors at Light/Balanced/Heavy. Maximum uses the three-character floor and also permits initialized writable data. Loader-owned and overlapping ranges remain excluded. |

## Runtime protection and analysis resistance

The following settings support Light:

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
| Native code and protected bodies | `integrity.measurement-channels` | Measures original functions and relocated protected bodies, including immutable VM bytecode, with a relocation-stable salted hash. |
| TLS callback ownership | `integrity.tls-veh-ownership` | Stores and verifies the final callback-array identity without depending on scrubbed headers. |
| Platform image mitigations | `integrity.mitigation-stack` | Asserts ASLR, high-entropy-VA, and DEP flags while preserving existing CFG metadata. |
| Integrity monitor thread | `integrity.hidden-threads` | Starts a monitor worker, applies `ThreadHideFromDebugger`, and records the PEB debugger signal. |
| Runtime key state | `response.silent-taint` | Idempotently taints session state on detection; opted-in startup string decryption consumes that key after startup checks. It does not re-encrypt previously decrypted strings. |
| Safe detection response | `response.tool-response` | Converts a shared detection flag into a clean process exit; no destructive response is implemented. |
| Build ownership | `response.brand-overlay` | Embeds a bounded build-specific owner/watermark record. |
| Support diagnostics | `response.custom-messages` | Embeds a bounded diagnostic record and emits it to the debugger when detection state is raised. |
| Post-start foreign loads | `nuclear.injection-hunter` | Classifies loader-notified module paths against runtime-captured application and Windows prefixes and records foreign loads. |

## Selected-function transforms and data packing

These Light-level settings require explicit selection:

| What is protected | Protection | Verified Light scope |
| --- | --- | --- |
| Initialized writable data | `packaging.packer` | Compresses eligible original RW data sections and restores them before other startup work, preserving RVAs and permissions. Code packing and unsupported loader metadata are rejected. |
| Selected native control flow | `code-transformation.flattening` | Rebuilds small, register-only, empty-unwind leaf functions with verified local conditional branches around a seeded state dispatcher. |
| Selected leaf-function logic | `virtualization.per-build-isa` | Emits a real bytecode interpreter with per-build opcode assignments for a verified straight-line scalar accumulator subset. |
| VM selection | `virtualization.coverage` | Requires explicit symbol/RVA selection or enabling rules, leaves unsupported functions native with logged reasons, and works together with the per-build ISA setting. |
| Integer SIMD operations | `virtualization.extended-isa` | Adds initialized XMM0/XMM1 MOVD/MOVQ, MOVDQA, packed dword/qword addition/subtraction, and bitwise operations. No memory, floating-point, string, or atomic instructions. |
| VM handler implementations | `virtualization.handler-polymorphism` | Selects equivalent arithmetic and register-dataflow implementations per interpreter using the build seed. |
| Nested virtualized operations | `virtualization.vm-nesting` | Executes outer operations through a disjoint micro-ISA with an independent instruction pointer and composed primitive programs. |
| Runtime bytecode copies | `virtualization.runtime-rekey` | Moves and re-encodes up to 32 outer instructions between private stack buffers after every instruction, scrubs replaced/returned buffers, and supplies native unwind metadata. Templates stay immutable; masks are not cryptographic encryption. |
| Conditional branch decisions | `nuclear.nanomites` | Evaluates saved flags at exact owned exception sites in explicitly selected acyclic integer leaf CFGs. |
| Native control-flow edges | `nuclear.exception-flow` | Routes selected edges through owned exceptions, preserves unrelated exception handling, and falls back to native code if handler registration fails. |

These native-body transforms currently reject load-configuration/CFG images and
preserve original public entry addresses through direct transfers. Virtualization
owns overlapping selections before exception flow and flattening run. Their private symbol maps
record the relocated body ranges. Packing currently rejects original TLS,
resources, complex unwind records, and other unsupported loader metadata; ordinary
imports and relocations must be entirely outside packed data. These restricted
emitters are off in every preset, including Nuclear.

Exception transforms require the entry dispatcher and a build-wide limit of 1,024
owned sites. Their first-chance exceptions remain visible to diagnostics tools,
and their cost suits infrequent paths. VM re-keying adds a described stack frame;
other VM variants and the exception handler preserve leaf unwinding conventions.

Environment probes, mapped-header changes, process-policy changes, response
behavior, and background monitors remain explicit opt-ins rather than preset
defaults. This keeps ordinary Balanced builds conservative while allowing a
release profile to select and compatibility-test each runtime measure.

These protections target PE32+ AMD64 executables. Native DLLs and
already-protected inputs are rejected by this backend. Authenticode signatures do
not survive a binary rewrite, so the protected output must be signed afterward.

## Managed IL protection

The managed backend operates on pure-IL assemblies without loading or executing
application code. Options are explicit under `Targets.Managed`; native presets
are rejected for managed inputs.

| Option | Scope | Behavior |
| --- | --- | --- |
| `Strings` | Eligible method bodies | Replaces eligible string loads with a generated decoder and protected payload while preserving metadata-owned resource, interop, and serialization uses. |
| `Constants` | Eligible method bodies | Rewrites verified integer constants while preserving stack behavior and exception semantics. |
| `ControlFlow` | Eligible methods | Rebuilds a bounded, typed int32 subset; unsupported bodies remain unchanged with a reason. |
| `Virtualize` | Explicitly selected methods | Converts a verified int32 method subset to a per-build interpreter. Selection is required and performance-sensitive methods should be measured. |
| `HardenedRuntime` | Explicitly selected modern .NET methods | Uses authenticated encrypted payloads and method-specific dispatch. Embedded application-side keys do not provide confidentiality from the running application. |
| `MetadataHygiene` | Assembly metadata | Removes supported build and symbol clues without changing the public API. |
| `Integrity` | Protector-owned payloads | Detects changes to Rampart-owned managed payloads; it is not whole-process integrity. |
| `RenamePrivateMembers` | Conservatively proven private/internal identities | Renames only identities whose reflection, serialization, interop, friend, and resource contracts can be preserved. |

Managed method rules can match assembly, module, namespace, type, method,
signature, metadata token, source document, and generated-code state. Keep
patterns and keep files preserve externally discovered identities. Strict
compatibility rejects unresolved reflection contracts; the default retains
uncertain names and reports the limitation.

Portable and embedded PDBs are rewritten with token and sequence-point mappings.
Opaque Windows PDBs require symbol preservation to be disabled. Strong-named
assemblies require a key selected through an environment-variable name; key paths
and key material do not belong in configuration or release artifacts. The output
receives structural verification and, when references are available, nominal
ECMA-335 verification. The private map records the verification engine, reference
scope, hashes, and per-method evidence.

## NativeAOT protection

Rampart recognizes eligible Windows x64 NativeAOT outputs by structure rather
than filename. The initial post-link backend intentionally allows only Light
`packaging.header-disguise` and Light `packaging.symbol-scrub`. It snapshots
runtime-owned PE, unwind, relocation, load-configuration, debug, and symbol data;
each pass is transactional and the output is rejected if an invariant changes.

NativeAOT method-body rewriting, runtime hooks, packing, managed options, and
ordinary native presets are not accepted after native compilation. Apply managed
IL protection before NativeAOT compilation, then use the post-link allowlist, and
finally apply Authenticode signing.

## MSBuild publish integration

`Rampart.MSBuild` is opt-in and disabled by default. It stages selected managed
assemblies before trimming, ReadyToRun, bundling, or NativeAOT compilation, and it
can stage the eligible NativeAOT output after linking. Compiler outputs remain
recoverable; protected artifacts and private manifests live in intermediate
directories. Cache keys include input, symbols, configuration, seed, target,
tool, dependency, and verification-reference hashes.

The main application assembly is selected automatically. Additional application
assemblies require explicit `RampartAssembly` items; framework and runtime-pack
assemblies are not selected implicitly. Publish protection runs before the
`RampartProtectionComplete` extension point so Authenticode and packaging can run
after every transformation.

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
- `code-transformation.flattening`
- `code-transformation.mba-constants`
- `virtualization.per-build-isa`
- `virtualization.coverage`
- `virtualization.extended-isa`
- `virtualization.handler-polymorphism`
- `virtualization.vm-nesting`
- `virtualization.runtime-rekey`
- `nuclear.nanomites`
- `nuclear.exception-flow`

Private symbol-map schema 2 separates actual per-function `Applied` evidence from
the effective `Requested` policy. A skipped transform appears only in `Requested`.

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

## Inspecting supported capabilities

This file explains coverage, but the CLI is the authority for the current
build. Use:

```powershell
dotnet run --project src/Rampart.Cli -- knobs
dotnet run --project src/Rampart.Cli -- knobs --json
dotnet run --project src/Rampart.Cli -- explain strings.encryption
dotnet run --project src/Rampart.Cli -- check --preset balanced --json
```

Use the build's applied-protection report to confirm which settings changed the
output. Configuration selection alone does not establish coverage.
