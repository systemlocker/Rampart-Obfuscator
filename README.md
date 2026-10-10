# Rampart

Rampart is an experimental, open-source protector for Windows applications. It
supports native x64 PE executables, pure managed IL assemblies, and eligible
Windows x64 NativeAOT publish outputs. Reproducible per-build transforms keep the
configuration and resulting changes inspectable.

Protect copies of your binaries, keep the original build artifacts, and test
protected output on every Windows version you
support. Obfuscation does not replace secure application design or server-side
validation of sensitive operations.

## Supported capabilities

Rampart provides PE metadata transforms, import-reference concealment, startup
string protection, selected native-function transformations, managed IL
protection, a conservative NativeAOT post-link stage, and opt-in runtime integrity
checks. It also includes an opt-in MSBuild package that protects publish artifacts
at the correct managed and NativeAOT stages.

`rampart inspect` classifies an artifact without loading or running it.
`rampart knobs` lists the shared protection settings, while target-specific
managed options live under the versioned `Targets` configuration object. Native
presets stay within verified level ceilings; unsupported requests fail instead of
silently downgrading.

See [Protection coverage](FEATURES.md) for supported mechanisms, selection
requirements, and compatibility limits.

| Protection | Verified through |
| --- | --- |
| Symbol scrub | Maximum |
| Import concealment | Light |
| PE header disguise | Maximum |
| Entry-point routing and disassembly confusion | Light |
| Junk/dead-code insertion | Maximum |
| Runtime-stub constant splitting | Light |
| Selected native-function constant splitting | Maximum |
| Per-build mutation | Light |
| Layered string encryption | Balanced |
| String decryptor/table integrity checks | Light |
| String coverage tuning | Maximum |
| IDA, Hex-Rays, symbolic, and static-decode resistance | Light |
| Runtime PE-signature, anti-dump, and section-table scrubbing | Light |
| Multi-channel anti-debug monitoring | Light |
| Virtualization, sandbox-artifact, and human-activity observations | Light |
| DACL, CET, dynamic-code, and IAT hardening | Light |
| Sensitive API wrapper concealment | Light |
| Runtime sentinels, code measurements, TLS ownership, and mitigation flags | Light |
| Hidden integrity-monitor thread and foreign-module observation | Light |
| Silent taint, clean exit, watermark, and diagnostic responses | Light |
| Initialized writable-data packing | Light |
| Selected leaf-function control-flow flattening | Light |
| Per-build leaf-function VM and explicit coverage | Light |
| Integer SSE2 virtualization and VM handler variants | Light |
| Nested VM and invocation-owned bytecode re-keying | Light |
| Exception-dispatched branches and control-flow edges | Light |

The native PE backend targets PE32+ AMD64 executables and preserves ASLR
relocations and overlays. The managed backend accepts supported pure-IL .NET
assemblies. The NativeAOT backend admits only structurally recognized Windows x64
outputs and a small verified pass allowlist. Apphosts, ReadyToRun images,
single-file bundles, mixed-mode assemblies, and already-protected inputs are
identified and rejected with stage-specific guidance. Because binary transforms
invalidate Authenticode, sign the protected output rather than the input binary.

## Install

The Windows x64 archive includes the .NET runtime. Extract the archive, then run:

```powershell
.\rampart.exe --version
.\rampart.exe knobs
```

To install the .NET tool with the .NET 8 SDK or newer:

```powershell
dotnet tool install --global rampart --version 0.3.1
rampart --version
```

The `Rampart.Core` NuGet package provides the transformation engine for .NET 8
applications. Add it with `dotnet add package Rampart.Core --version 0.3.1`.
`Rampart.MSBuild` provides disabled-by-default publish integration; reference it
with `PrivateAssets="all"` at the same version as the tool.

## Build

Install the .NET 8 SDK, then run:

```powershell
dotnet build Rampart.slnx
```

The core library builds cross-platform. Run and verify protected executables on
the Windows versions supported by your application.

## Quick start

Preview the exact resolved configuration without writing output:

```powershell
dotnet run --project src/Rampart.Cli -- protect path\to\app.exe `
  --preset balanced --seed 12345 --dry-run --json
```

Protect and inspect it:

```powershell
dotnet run --project src/Rampart.Cli -- protect path\to\app.exe `
  --preset balanced --seed 12345 --out app.protected.exe

dotnet run --project src/Rampart.Cli -- inspect app.protected.exe
```

Use `--force` to replace an existing output file. Rampart always refuses to use
the input path itself as the output path.

### Managed .NET quick start

Managed protection is explicit; native presets do not apply to managed IL. Start
with a small configuration and review the private evidence map produced beside the
output:

```json
{
  "Seed": 12345,
  "Targets": {
    "Version": 1,
    "Managed": {
      "Strings": true,
      "Constants": true,
      "MetadataHygiene": true
    }
  }
}
```

```powershell
rampart inspect path\to\Application.dll --json
rampart protect path\to\Application.dll `
  --config rampart-managed.json --out Application.protected.dll
```

Rampart preserves supported portable or embedded PDBs, verifies emitted IL, and
records applied, skipped, and rejected work per method. Unsupported methods stay
unchanged with a reason. Keep `.rmap.json` files, PDBs, keep lists, and signing
keys with private build artifacts rather than distributing them.

### Publish integration

Add the package and enable it only for the publish configurations you have tested:

```xml
<ItemGroup>
  <PackageReference Include="Rampart.MSBuild" Version="0.3.1" PrivateAssets="all" />
</ItemGroup>

<PropertyGroup>
  <RampartEnabled>true</RampartEnabled>
  <RampartSeed>12345</RampartSeed>
  <RampartConfiguration>$(MSBuildProjectDirectory)/rampart-managed.json</RampartConfiguration>
</PropertyGroup>
```

The integration stages pure IL before trimming, ReadyToRun, bundling, or
NativeAOT compilation. For NativeAOT publishes it can also apply the separate
post-link NativeAOT allowlist before Authenticode signing. Additional application
assemblies must be selected explicitly with `RampartAssembly`; runtime-pack
assemblies are never selected implicitly. Attach signing after the
`RampartProtectionComplete` target.

## Configuration

Useful discovery commands:

```powershell
dotnet run --project src/Rampart.Cli -- knobs
dotnet run --project src/Rampart.Cli -- explain strings.encryption
dotnet run --project src/Rampart.Cli -- check --preset balanced --json
```

Override one or more settings with `--set <id>=<level>`:

```powershell
dotnet run --project src/Rampart.Cli -- protect ExampleApp.exe `
  --preset balanced `
  --set code-transformation.junk-insertion=heavy `
  --seed 88442211
```

For focused profiles, `--only` turns everything else off and automatically adds
required startup dependencies. `--disable` is applied last, and `--group-level`
sets every ready protection in a group while respecting each emitter's ceiling:

```powershell
# Protect strings, plus the entry-point dispatcher required to decrypt them.
dotnet run --project src/Rampart.Cli -- protect ExampleApp.exe `
  --only strings.encryption,strings.coverage

# Start Balanced, strengthen ready code transforms, then opt one feature out.
dotnet run --project src/Rampart.Cli -- protect ExampleApp.exe `
  --preset balanced `
  --group-level code-transformation=maximum `
  --disable code-transformation.mba-constants
```

Bulk group levels clamp to verified emitter ceilings; exact `--set` requests stay
strict and fail if that particular level is not implemented. A final `--disable`
that turns off a required dependency also fails validation with an explanation.

Levels are `off`, `light`, `balanced`, `heavy`, and `maximum`. Unsupported settings
and levels fail validation instead of being reported as applied.
Configuration JSON emitted by `--dry-run --json` can be loaded with
`--config <file>`. Configuration property names are case-insensitive, while
unknown properties and null required collections are rejected so a typo cannot
silently fall back to a preset default.

### Function and region policies

Rampart can ingest MSVC or GNU linker MAP files, JSON symbol lists, and native
PDB public symbols before the normal symbol-scrub pass. PDB reading uses
`llvm-pdbutil`; put it on `PATH` or pass `--pdb-tool <file>`. These inputs remain
build-only and are never copied into the protected executable.

```powershell
dotnet run --project src/Rampart.Cli -- protect ExampleApp.exe `
  --map ExampleApp.map `
  --include-symbol 'ExampleApp::License::*' `
  --exclude-symbol 'ExampleApp::Renderer::*' `
  --rva-range 0x14200-0x14980 `
  --function-profile 'ExampleApp::ValidatePurchase=maximum'
```

For module, section, namespace, source-file, or mixed policies, use ordered
`Rules` in a configuration file. The last matching rule wins per protection.
Function-level policy applies to import-reference concealment, junk insertion, target constant splitting, string
encryption, string anti-instrumentation, and string coverage; image-wide PE and
startup transforms continue to use the global level.

The Light VM, exception-flow transforms, and control-flow flattening accept function policies, but
require explicit symbol/RVA selection or a matching enabling rule. These
native-body emitters accept only small, single-entry, register-only leaf functions
with empty unwind records. They leave unsupported functions native and explain
each skip in the build log. The VM supports a straight-line scalar accumulator
subset with an optional integer SSE2 extension; flattening and exception flow
support a conditional 32-bit register-only control-flow subset.
These transforms reject load-configuration/CFG images. For overlapping selections,
virtualization has priority, followed by exception flow, flattening, then native junk
and constant rewriting. Later passes never rewrite a body already owned by an
earlier native transform.

Balanced MBA splits target immediates in the verified 32-bit native subset.
Heavy nests two reconstruction layers; Maximum varies three or four layers of
arithmetic, XOR, and rotation per constant. The original instruction's flags are
preserved at every level.
Balanced through Maximum junk levels add increasing densities of executed,
flag-preserving noise; Heavy and Maximum also add branches over cold gadgets.
These body transforms require explicit function selection. If only padding noise
or generated-stub constants were changed, the applied report records Light—not
the higher requested native-body level. Flags live across branches and loops are
preserved, and unsafe constant rewrites are skipped.

```powershell
dotnet run --project src/Rampart.Cli -- protect ExampleApp.exe `
  --map ExampleApp.map --include-symbol 'ExampleApp::ComputeValue' `
  --only virtualization.coverage
```

`--only virtualization.coverage` enables both required VM settings. Explicit
`--set` and per-function rules must enable `virtualization.per-build-isa` and
`virtualization.coverage` together. All presets keep these native-body transforms
and packing off until explicitly selected.

VM extensions can be selected with `--only virtualization.extended-isa`,
`--only virtualization.handler-polymorphism`, `--only virtualization.vm-nesting`,
or `--only virtualization.runtime-rekey`; each adds the required VM pair. Exact
overrides and function rules must leave that pair enabled. These extensions also
stay off in every preset.

The integer SSE2 extension supports register-only MOVD/MOVQ, MOVDQA, packed
dword/qword addition and subtraction, and bitwise operations on XMM0/XMM1.
Vector state must be initialized inside the function, and the result returns
through EAX/RAX. Memory, floating-point, string, and atomic operations remain
outside this subset. Handler variants change actual arithmetic and register
dataflow. Nested execution uses a second, disjoint primitive ISA with its own
instruction pointer and immutable microcode.

Runtime re-keying supports at most 32 outer bytecode instructions. Each call
owns two stack buffers and moves/re-encodes its records after each instruction,
erasing replaced copies and scrubbing the buffers on return. The generated frame
has Windows unwind metadata. Shared code and templates remain immutable; operand
masks provide diversification rather than cryptographic encryption.

`nuclear.nanomites` resolves selected branch decisions from saved exception flags.
`nuclear.exception-flow` represents selected edges through exceptions. Both require
explicit function selection, an acyclic CFG, and the entry dispatcher. They own
only exact generated UD2 sites and leave unrelated exceptions to the application.
Registration failure retains a native fallback. Expected first-chance exceptions
remain visible to debuggers and crash tooling; use these settings on infrequent
paths and account for their exception-dispatch cost. A build is limited to 1,024
owned sites.

Light `packaging.packer` compresses only original initialized writable data
sections, not executable code. It restores their bytes at startup while keeping
their virtual addresses and page permissions. It rejects TLS, load-configuration,
resource, complex unwind, and other unsupported loader metadata, and rejects
sections containing loader-owned data or relocation targets. This is a narrow
data-packing contract, not a general-purpose full-image packer.

### Import and string boundaries

Light import concealment performs seeded export-name hash lookup and exact
name verification, with Windows `GetProcAddress` handling final binding and
forwarded exports. Original import names, descriptors, and IAT bindings remain
intact for loader ownership and unrewritten references. Ordinal/API-set imports
and unsupported reference forms stay unchanged; Light does not hide the original
import-name inventory.

String discovery follows decoded address-taking references to terminated printable
ASCII or BMP UTF-16LE data; surrogate pairs and control characters are not covered.
Shared references use the least-permissive policy, overlapping
string ranges are skipped, and loader-owned metadata is excluded. Coverage floors
are six characters at Light, eight at Balanced, and three at Heavy/Maximum;
Maximum additionally permits initialized writable data. Unsupported metadata,
shared section pages, and CFG images with pre-existing TLS may limit coverage.

String anti-instrumentation checks the decryptor's instruction range and its
record table before using them. It detects modifications to those checked bytes;
it is not a general debugger detector or a claim of resistance to every form of
instrumentation. Decryption temporarily changes page permissions and restores
their previous values. Explicit silent taint binds startup decryption keys to the
shared session state, after startup detections have been processed. This does not
re-encrypt strings already materialized in memory; they remain plaintext after
startup decryption.

When a response is selected, detections raised by the string checks are consumed
before the original entry point runs. Code integrity measurements cover both the
original function entries and relocated protected bodies, including VM bytecode.

Every successful build writes a private `<output-name>.rmap.json` sidecar by
default. It records original/protected RVAs, function identity, hashes, and the
effective per-function settings for crash-symbolication and build telemetry.
Relocated functions additionally record the emitted body's address, size, and
owning transformation; the original address and size remain available.
Keep this file with private build artifacts, not beside the distributed application.
Use `--symbol-map <file>` to choose its location or `--no-symbol-map` to opt out.

### PE compatibility

Preflight explicitly inventories and validates delay and bound imports, load
configuration/CFG metadata, existing TLS callback arrays, CET continuation
metadata, declared section/file alignment, and overlays. Rampart preserves these
structures. Existing TLS arrays are chained on ordinary images; for CFG images,
startup work is routed through a newly registered guarded entry target so the
original TLS metadata remains intact. `rampart inspect` reports the detected
compatibility surface.

Validate a protected copy against the original application before distribution.
Check startup, representative workloads, plug-in loading, crash reporting, and
signing workflows, along with output size and runtime overhead. Compatibility
depends on the input binary and the selected protections.

## Design principles

- Preserve behavior before adding protection depth.
- Make the same seed byte-reproducible and different seeds materially distinct.
- Never claim a catalog feature was applied unless its emitter ran.
- Validate emitted PE structures with independent Windows tooling and native
  execution, not only with Rampart's own parser.
- Prefer compatibility failures at build time over mysterious startup crashes.

Rampart intentionally focuses on software protection. Destructive retaliation,
security-tool corruption, and stealth intended to bypass endpoint monitoring are
outside the implementation scope.

## License

Rampart is dedicated to the public domain under
[CC0 1.0 Universal](LICENSE). No attribution is required.
