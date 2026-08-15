# Rampart

Rampart is an experimental, open-source Windows PE protector aimed at games and
small native applications. It reshapes x64 executables with reproducible,
per-build transforms while keeping the build configuration and resulting changes
inspectable.

The project is early-stage software. Protect copies of your binaries, keep the
original build artifacts, and test protected output on every Windows version you
support. Obfuscation can raise the cost of reverse engineering substantially.

## Current status

Rampart's catalog doubles as its roadmap. `rampart knobs` labels every entry as
ready or planned, and the engine rejects a requested level that does not yet have
a working emitter. Presets are automatically clamped to the highest verified
level for each ready protection.

| Protection | Verified through |
| --- | --- |
| Symbol scrub | Heavy |
| Import concealment | Light |
| PE header disguise | Balanced |
| Entry-point routing and disassembly confusion | Light |
| Junk/dead-code insertion | Maximum |
| Runtime-stub constant splitting | Light |
| Per-build mutation | Light |
| Layered string encryption | Balanced |
| String anti-instrumentation sentinels | Light |
| String coverage tuning | Maximum |

The build pipeline currently targets PE32+ AMD64 images. Its native integration
test generates a small Windows executable, protects it with the Balanced preset,
executes the result under ASLR, and verifies that behavior is preserved.
Native executable overlays are retained after the new Rampart section. DLLs,
managed .NET images, and already-protected inputs are rejected during preflight.
Because transforms invalidate Authenticode, sign the protected output rather than
the input binary.

## Build and test

Install the .NET 8 SDK, then run:

```powershell
dotnet build Rampart.slnx
dotnet test Rampart.slnx
```

The core library and PE generation tests are cross-platform. Native execution
verification runs only on Windows.

## Quick start

Generate the self-contained test executable:

```powershell
dotnet run --project src/Rampart.Cli -- sample --out game-sample.exe
```

Preview the exact resolved configuration without writing output:

```powershell
dotnet run --project src/Rampart.Cli -- protect game-sample.exe `
  --preset balanced --seed 12345 --dry-run --json
```

Protect and inspect it:

```powershell
dotnet run --project src/Rampart.Cli -- protect game-sample.exe `
  --preset balanced --seed 12345 --out game-sample.protected.exe

dotnet run --project src/Rampart.Cli -- inspect game-sample.protected.exe
```

Use `--force` to replace an existing output file. Rampart always refuses to use
the input path itself as the output path.

## Configuration

Useful discovery commands:

```powershell
dotnet run --project src/Rampart.Cli -- knobs --ready
dotnet run --project src/Rampart.Cli -- explain strings.encryption
dotnet run --project src/Rampart.Cli -- check --preset balanced --json
```

Override one or more settings with `--set <id>=<level>`:

```powershell
dotnet run --project src/Rampart.Cli -- protect BirdRodeo.exe `
  --preset balanced `
  --set code-transformation.junk-insertion=heavy `
  --seed 88442211
```

For focused profiles, `--only` turns everything else off and automatically adds
required startup dependencies. `--disable` is applied last, and `--group-level`
sets every ready protection in a group while respecting each emitter's ceiling:

```powershell
# Protect strings, plus the entry-point dispatcher required to decrypt them.
dotnet run --project src/Rampart.Cli -- protect BirdRodeo.exe `
  --only strings.encryption,strings.coverage

# Start Balanced, strengthen ready code transforms, then opt one feature out.
dotnet run --project src/Rampart.Cli -- protect BirdRodeo.exe `
  --preset balanced `
  --group-level code-transformation=maximum `
  --disable code-transformation.mba-constants
```

Bulk group levels clamp to verified emitter ceilings; exact `--set` requests stay
strict and fail if that particular level is not implemented. A final `--disable`
that turns off a required dependency also fails validation with an explanation.

Levels are `off`, `light`, `balanced`, `heavy`, and `maximum`. A planned knob or
an unimplemented level fails clearly instead of being reported as applied.
Configuration JSON emitted by `--dry-run --json` can be loaded with
`--config <file>`.

### Function and region policies

Rampart can ingest MSVC or GNU linker MAP files, JSON symbol lists, and native
PDB public symbols before the normal symbol-scrub pass. PDB reading uses
`llvm-pdbutil`; put it on `PATH` or pass `--pdb-tool <file>`. These inputs remain
build-only and are never copied into the protected executable.

```powershell
dotnet run --project src/Rampart.Cli -- protect BirdRodeo.exe `
  --map BirdRodeo.map `
  --include-symbol 'BirdRodeo::License::*' `
  --exclude-symbol 'BirdRodeo::Renderer::*' `
  --rva-range 0x14200-0x14980 `
  --function-profile 'BirdRodeo::ValidatePurchase=maximum'
```

For module, section, namespace, source-file, or mixed policies, use ordered
`Rules` in a configuration file. The last matching rule wins per protection.
`samples/bird-rodeo.rules.json` is a complete example. Current function-level
policy applies to import-reference concealment, junk insertion, string
encryption, string anti-instrumentation, and string coverage; image-wide PE and
startup transforms continue to use the global level.

Every successful build writes a private `<output-name>.rmap.json` sidecar by
default. It records original/protected RVAs, function identity, hashes, and the
effective per-function settings for crash-symbolication and build telemetry.
Keep this file with private build artifacts, not beside the distributed game.
Use `--symbol-map <file>` to choose its location or `--no-symbol-map` to opt out.

### PE compatibility

Preflight explicitly inventories and validates delay and bound imports, load
configuration/CFG metadata, existing TLS callback arrays, CET continuation
metadata, declared section/file alignment, and overlays. Rampart preserves these
structures. Existing TLS arrays are chained on ordinary images; for CFG images,
startup work is routed through a newly registered guarded entry target so the
original TLS metadata remains intact. `rampart inspect` reports the detected
compatibility surface.

Compatibility validation pins FFmpeg, SQLite, 7-Zip, curl, Lua, Git-for-Windows
utilities, and SDL. It checks exact behavior, hashes, output growth, and median
startup time across runs. Our goal is to have absolute certainty in the 
capabilities of Rampart.

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
