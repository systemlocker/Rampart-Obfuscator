namespace Rampart.Config;

/// <summary>Protection metadata used by configuration and CLI discovery.
/// Identifiers are stable; descriptions cover supported behavior only.</summary>
public static class KnobCatalogData
{
    // Four array positions retain the established Light..Maximum data shape.
    // Unsupported levels carry no budget or behavioral description.
    public static readonly IEnumerable<KnobDef> Entries =
    [
        new("packaging.symbol-scrub", KnobGroups.Packaging, "Symbol scrub",
            "Removes debug-directory and PDB-path data, the Rich header, section names, COFF symbol remnants, and build timestamps according to level.",
            [1, 1, 1, 0],
            [
                "Strips the debug directory and any embedded PDB path from the image.",
                "Also zeroes the Rich header and blanks section names in the section table.",
                "Also zeroes timestamp fields across the headers (TimeDateStamp and the export/import table clocks).",
                "Not supported at this level.",
            ],
            [ThreatTags.Static]),

        new("packaging.import-concealment", KnobGroups.Packaging, "Import concealment",
            "Routes eligible references through seeded export-name hash lookup with exact collision verification and Windows-managed final binding. Original loader import names and bindings remain intact.",
            [1, 0, 0, 0],
            [
                "Routes eligible references through seeded export-name hash lookup with exact collision verification and Windows-managed final binding. Original loader import names and bindings remain intact.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static, ThreatTags.Dump]),

        new("packaging.header-disguise", KnobGroups.Packaging, "Header disguise",
            "Replaces genuine timestamp and selected linker metadata with build-seeded decoy values.",
            [1, 1, 0, 0],
            [
                "Replaces the COFF timestamp and linker version with build-seeded values.",
                "Also writes a decoy PDB path into DOS-stub slack when sufficient space is available.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static]),

        new("packaging.ep-confusion", KnobGroups.Packaging, "Entry-point confusion",
            "Routes startup through a generated dispatcher which computes and transfers control to the original entry point.",
            [1, 0, 0, 0],
            [
                "Routes startup through a generated dispatcher which computes and transfers control to the original entry point.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static, ThreatTags.Dump]),

        new("packaging.packer", KnobGroups.Packaging, "Section packer",
            "Compresses eligible original RW data sections and restores them before other startup work, preserving RVAs and permissions. Code packing and unsupported loader metadata are rejected.",
            [2, 0, 0, 0],
            [
                "Compresses eligible original RW data sections and restores them before other startup work, preserving RVAs and permissions. Code packing and unsupported loader metadata are rejected.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static, ThreatTags.Dump]),

        new("strings.encryption", KnobGroups.StringProtection, "Layered string encryption",
            "Encrypts eligible referenced string runs in place and restores them during protected startup.",
            [1, 1, 0, 0],
            [
                "Encrypts eligible printable ASCII and BMP UTF-16LE strings with per-string rotating XOR keys; restores them at startup.",
                "Adds a rolling per-byte algebraic layer. Decrypted strings remain plaintext after startup.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static]),

        new("strings.anti-instrumentation", KnobGroups.StringProtection, "String integrity checks",
            "Checks the decryptor instruction range and record table before use; detected modifications leave the affected strings encrypted and record a shared detection flag.",
            [1, 0, 0, 0],
            [
                "Checks the decryptor instruction range and record table before use; detected modifications leave the affected strings encrypted and record a shared detection flag.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Debug, ThreatTags.Tools]),

        new("strings.coverage", KnobGroups.StringProtection, "Coverage tuning",
            "Selects referenced ASCII/UTF-16LE strings with six/eight/three-character floors at Light/Balanced/Heavy. Maximum uses the three-character floor and also permits initialized writable data. Loader-owned and overlapping ranges remain excluded.",
            [0, 0, 0, 0],
            [
                "Protects referenced ASCII/UTF-16LE strings of six or more characters in read-only initialized data.",
                "Raises the floor to eight characters; loader-owned metadata and overlapping candidates remain excluded.",
                "Includes referenced read-only strings of three or more characters under the same conservative exclusions.",
                "Additionally permits referenced initialized writable data, with the three-character floor and all ownership exclusions retained.",
            ],
            [ThreatTags.Static]),

        new("code-transformation.junk-insertion", KnobGroups.CodeTransformation, "Junk insertion",
            "Light fills verified padding; higher levels additionally rewrite explicitly selected, verified register-only leaf bodies with increasing in-body noise density. Heavy/Maximum include bounded dead branches. Padding alone reports Light.",
            [1, 1, 2, 3],
            [
                "Fills verified inter-function padding with seeded decoy instructions.",
                "Adds executed flag-neutral noise at instruction sites in explicitly selected, verified 32-bit register-only leaf functions.",
                "Doubles in-body noise density and adds direct branches over bounded cold gadgets within the same verified subset.",
                "Uses the highest bounded noise density and cold gadgets in eligible selected bodies; unsupported functions stay native and padding-only work reports Light.",
            ],
            [ThreatTags.Static]),

        new("code-transformation.mba-constants", KnobGroups.CodeTransformation, "MBA constants",
            "Light splits generated constants; Balanced additionally reconstructs eligible target immediates through seeded modular arithmetic/boolean identities, preserving live flags. Stub-only work reports Light.",
            [1, 1, 0, 0],
            [
                "XOR-splits constants in Rampart-generated runtime stubs.",
                "Reconstructs eligible immediates in explicitly selected 32-bit leaf functions with seeded modular arithmetic and XOR; preserves live flags and reports stub-only work as Light.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("code-transformation.per-build-mutation", KnobGroups.CodeTransformation, "Per-build mutation",
            "Changes generated layout choices, register allocation, keys, and related emitted bytes from the build seed.",
            [1, 0, 0, 0],
            [
                "Changes generated layout choices, register allocation, keys, and related emitted bytes from the build seed.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static]),

        new("code-transformation.flattening", KnobGroups.CodeTransformation, "Control-flow flattening",
            "Rebuilds small, register-only, empty-unwind leaf functions with verified local conditional branches around a seeded state dispatcher.",
            [1, 0, 0, 0],
            [
                "Rebuilds small, register-only, empty-unwind leaf functions with verified local conditional branches around a seeded state dispatcher.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("anti-debug.channel-sweep", KnobGroups.AntiDebug, "Debug channel sweep",
            "Cross-checks `IsDebuggerPresent`, `PEB.BeingDebugged`, and `CheckRemoteDebuggerPresent` into shared detection state.",
            [1, 0, 0, 0],
            [
                "Cross-checks `IsDebuggerPresent`, `PEB.BeingDebugged`, and `CheckRemoteDebuggerPresent` into shared detection state.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Debug]),

        new("anti-debug.inline-hook-check", KnobGroups.AntiDebug, "Inline hook check",
            "Captures salted prologue fingerprints and detects common trampoline signatures for selected ntdll exports.",
            [1, 0, 0, 0],
            [
                "Captures salted prologue fingerprints and detects common trampoline signatures for selected ntdll exports.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Debug, ThreatTags.Tools]),

        new("anti-debug.veh-tamper", KnobGroups.AntiDebug, "VEH tamper check",
            "Registers a first-priority passive VEH and verifies delivery with a private continuable exception.",
            [1, 0, 0, 0],
            [
                "Registers a first-priority passive VEH and verifies delivery with a private continuable exception.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Debug]),

        new("anti-debug.dll-notify", KnobGroups.AntiDebug, "Load notifications",
            "Registers an `LdrRegisterDllNotification` callback and records loader-mediated module events.",
            [1, 0, 0, 0],
            [
                "Registers an `LdrRegisterDllNotification` callback and records loader-mediated module events.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Inject, ThreatTags.Tools]),

        new("anti-inject.dacl-hardening", KnobGroups.AntiInject, "DACL hardening",
            "Applies a process DACL denying new create-thread and VM-write opens while retaining ordinary query access.",
            [1, 0, 0, 0],
            [
                "Applies a process DACL denying new create-thread and VM-write opens while retaining ordinary query access.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Inject]),

        new("anti-inject.cet-shadow-stack", KnobGroups.AntiInject, "CET shadow stack",
            "Emits the Windows CET-compatible image characteristic so supported systems can enforce hardware shadow stacks.",
            [1, 0, 0, 0],
            [
                "Emits the Windows CET-compatible image characteristic so supported systems can enforce hardware shadow stacks.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Inject, ThreatTags.Kernel]),

        new("anti-inject.dynamic-code-policy", KnobGroups.AntiInject, "Dynamic code policy",
            "Applies `ProcessDynamicCodePolicy` during protected startup and records policy rejection.",
            [1, 0, 0, 0],
            [
                "Applies `ProcessDynamicCodePolicy` during protected startup and records policy rejection.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Inject]),

        new("anti-inject.iat-hash-check", KnobGroups.AntiInject, "Import hash check",
            "Baselines IAT targets after loader resolution and rechecks them from Rampart's TLS monitor.",
            [1, 0, 0, 0],
            [
                "Baselines IAT targets after loader resolution and rechecks them from Rampart's TLS monitor.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Inject, ThreatTags.Tools]),

        new("anti-sandbox.virtualisation-detect", KnobGroups.AntiSandbox, "Virtualisation detect",
            "Records the CPUID hypervisor bit and vendor tuple as evidence without changing application behavior.",
            [1, 0, 0, 0],
            [
                "Records the CPUID hypervisor bit and vendor tuple as evidence without changing application behavior.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Sandbox]),

        new("anti-sandbox.fingerprint-suite", KnobGroups.AntiSandbox, "Sandbox fingerprints",
            "Checks exact loaded-module names and environment variables from common sandbox families.",
            [1, 0, 0, 0],
            [
                "Checks exact loaded-module names and environment variables from common sandbox families.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Sandbox, ThreatTags.Tools]),

        new("anti-sandbox.human-gate", KnobGroups.AntiSandbox, "Recent-input observation",
            "Records whether `GetLastInputInfo` exceeds a conservative 30-minute idle window.",
            [1, 0, 0, 0],
            [
                "Records whether `GetLastInputInfo` exceeds a conservative 30-minute idle window.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Sandbox]),

        new("analysis.ida-bomb", KnobGroups.AnalysisCrashers, "Static-analysis decoys",
            "Adds 256 bounded cold synthetic functions connected by valid direct-call cross-references.",
            [1, 0, 0, 0],
            [
                "Adds 256 bounded cold synthetic functions connected by valid direct-call cross-references.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("analysis.hexrays-denial", KnobGroups.AnalysisCrashers, "Decompiler decoys",
            "Adds cold opaque control-flow and relative jump-table decoys without malformed instructions.",
            [1, 0, 0, 0],
            [
                "Adds cold opaque control-flow and relative jump-table decoys without malformed instructions.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("analysis.symbolic-denial", KnobGroups.AnalysisCrashers, "Symbolic-analysis decoys",
            "Adds bounded cold nonlinear constraint gadgets that do not enter the real execution path.",
            [1, 0, 0, 0],
            [
                "Adds bounded cold nonlinear constraint gadgets that do not enter the real execution path.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("analysis.static-decode-denial", KnobGroups.AnalysisCrashers, "Disassembly decoys",
            "Adds bounded cold overlapping-decode gadgets for which linear and branch-following interpretations differ.",
            [1, 0, 0, 0],
            [
                "Adds bounded cold overlapping-decode gadgets for which linear and branch-following interpretations differ.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static]),

        new("analysis.runtime-header-corruption", KnobGroups.AnalysisCrashers, "Mapped signature clearing",
            "Clears mapped MZ and PE signatures after loader initialization, restoring the original page protection afterward.",
            [1, 0, 0, 0],
            [
                "Clears mapped MZ and PE signatures after loader initialization, restoring the original page protection afterward.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Dump]),

        new("memory.anti-dump", KnobGroups.MemoryProtection, "Reconstruction metadata clearing",
            "Clears mapped section names, raw sizes/pointers, and obsolete COFF reconstruction fields.",
            [2, 0, 0, 0],
            [
                "Clears mapped section names, raw sizes/pointers, and obsolete COFF reconstruction fields.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Dump]),

        Unsupported("memory.at-rest-encryption", KnobGroups.MemoryProtection, [ThreatTags.Dump]),

        new("memory.api-concealment", KnobGroups.MemoryProtection, "API concealment",
            "Rewrites eligible direct IAT calls and jumps through protector-owned local tail thunks.",
            [1, 0, 0, 0],
            [
                "Rewrites eligible direct IAT calls and jumps through protector-owned local tail thunks.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static, ThreatTags.Dump]),

        Unsupported("memory.stack-spoof", KnobGroups.MemoryProtection, [ThreatTags.Dump, ThreatTags.Debug]),

        Unsupported("memory.page-mode-decrypt", KnobGroups.MemoryProtection, [ThreatTags.Dump, ThreatTags.Static]),

        Unsupported("memory.sleep-mask", KnobGroups.MemoryProtection, [ThreatTags.Dump]),

        new("virtualization.per-build-isa", KnobGroups.Virtualization, "Per-build ISA",
            "Emits a real bytecode interpreter with per-build opcode assignments for a verified straight-line scalar accumulator subset.",
            [1, 0, 0, 0],
            [
                "Emits a scalar leaf-function interpreter with build-seeded opcode assignments, encoded operands, and register mapping; unsupported functions remain native.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("virtualization.coverage", KnobGroups.Virtualization, "VM coverage",
            "Requires explicit symbol/RVA selection or enabling rules, leaves unsupported functions native with logged reasons, and works together with the per-build ISA setting.",
            [1, 0, 0, 0],
            [
                "Requires explicit symbol/RVA selection or enabling rules, leaves unsupported functions native with logged reasons, and works together with the per-build ISA setting.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        Unsupported("virtualization.extended-isa", KnobGroups.Virtualization, [ThreatTags.Static, ThreatTags.Tools]),

        Unsupported("virtualization.handler-polymorphism", KnobGroups.Virtualization, [ThreatTags.Static, ThreatTags.Tools]),

        Unsupported("virtualization.vm-nesting", KnobGroups.Virtualization, [ThreatTags.Static, ThreatTags.Tools]),

        Unsupported("virtualization.jit-handlers", KnobGroups.Virtualization, [ThreatTags.Dump, ThreatTags.Tools]),

        Unsupported("virtualization.runtime-rekey", KnobGroups.Virtualization, [ThreatTags.Dump, ThreatTags.Static]),

        Unsupported("virtualization.decoy-bodies", KnobGroups.Virtualization, [ThreatTags.Static]),

        new("integrity.kernel-wall", KnobGroups.IntegrityBinding, "Integrity sentinels",
            "Emits build-specific self-hashed sentinel words and records later modifications.",
            [1, 0, 0, 0],
            [
                "Emits build-specific self-hashed sentinel words and records later modifications.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Kernel, ThreatTags.Dump]),

        new("integrity.measurement-channels", KnobGroups.IntegrityBinding, "Measurement channels",
            "Measures original functions and relocated protected bodies, including immutable VM bytecode, with a relocation-stable salted hash.",
            [1, 0, 0, 0],
            [
                "Measures original functions and relocated protected bodies, including immutable VM bytecode, with a relocation-stable salted hash.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static, ThreatTags.Kernel]),

        Unsupported("integrity.self-debug-port", KnobGroups.IntegrityBinding, [ThreatTags.Debug, ThreatTags.Dump]),

        new("integrity.tls-veh-ownership", KnobGroups.IntegrityBinding, "TLS/VEH ownership",
            "Stores and verifies the final callback-array identity without depending on scrubbed headers.",
            [1, 0, 0, 0],
            [
                "Stores and verifies the final callback-array identity without depending on scrubbed headers.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Debug, ThreatTags.Tools]),

        new("integrity.header-scrub", KnobGroups.IntegrityBinding, "Runtime header scrub",
            "Clears every mapped section-table entry after startup while leaving the on-disk PE valid.",
            [1, 0, 0, 0],
            [
                "Clears every mapped section-table entry after startup while leaving the on-disk PE valid.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Dump]),

        new("integrity.hidden-threads", KnobGroups.IntegrityBinding, "Integrity monitor worker",
            "Starts a monitor worker, applies `ThreadHideFromDebugger`, and records the PEB debugger signal.",
            [1, 0, 0, 0],
            [
                "Starts a monitor worker, applies `ThreadHideFromDebugger`, and records the PEB debugger signal.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Debug, ThreatTags.Tools]),

        Unsupported("integrity.loader-hijack", KnobGroups.IntegrityBinding, [ThreatTags.Inject]),

        new("integrity.mitigation-stack", KnobGroups.IntegrityBinding, "Mitigation stack",
            "Asserts ASLR, high-entropy-VA, and DEP flags while preserving existing CFG metadata.",
            [1, 0, 0, 0],
            [
                "Asserts ASLR, high-entropy-VA, and DEP flags while preserving existing CFG metadata.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Inject, ThreatTags.Kernel]),

        new("response.silent-taint", KnobGroups.Response, "Silent taint",
            "Idempotently taints session state on detection; opted-in startup string decryption consumes that key after startup checks. It does not re-encrypt previously decrypted strings.",
            [1, 0, 0, 0],
            [
                "Idempotently taints session state on detection; opted-in startup string decryption consumes that key after startup checks. It does not re-encrypt previously decrypted strings.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Debug, ThreatTags.Tools]),

        Unsupported("nuclear.nanomites", KnobGroups.Response, [ThreatTags.Static, ThreatTags.Debug, ThreatTags.Tools]),

        Unsupported("nuclear.exception-flow", KnobGroups.Response, [ThreatTags.Static, ThreatTags.Tools]),

        new("response.tool-response", KnobGroups.Response, "Detection response",
            "Converts a shared detection flag into a clean process exit; no destructive response is implemented.",
            [1, 0, 0, 0],
            [
                "Converts a shared detection flag into a clean process exit; no destructive response is implemented.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Tools, ThreatTags.Sandbox]),

        Unsupported("nuclear.memory-ambush", KnobGroups.Response, [ThreatTags.Dump, ThreatTags.Tools]),

        new("nuclear.injection-hunter", KnobGroups.Response, "Foreign-module monitoring",
            "Classifies loader-notified module paths against runtime-captured application and Windows prefixes and records foreign loads.",
            [1, 0, 0, 0],
            [
                "Classifies loader-notified module paths against runtime-captured application and Windows prefixes and records foreign loads.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Inject]),

        new("response.brand-overlay", KnobGroups.Response, "Owner watermark",
            "Embeds a bounded build-specific owner/watermark record.",
            [1, 0, 0, 0],
            [
                "Embeds a bounded build-specific owner/watermark record.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static]),

        new("response.custom-messages", KnobGroups.Response, "Custom messages",
            "Embeds a bounded diagnostic record and emits it to the debugger when detection state is raised.",
            [1, 0, 0, 0],
            [
                "Embeds a bounded diagnostic record and emits it to the debugger when detection state is raised.",
                "Not supported at this level.",
                "Not supported at this level.",
                "Not supported at this level.",
            ],
            [ThreatTags.Static]),

    ];

    // Recognize disabled identifiers from existing configuration files without
    // advertising unavailable functionality or accepting an enabled override.
    private static KnobDef Unsupported(string id, string group, string[] tags) =>
        new(id, group, "Unsupported option", "This option is not supported.",
            [0, 0, 0, 0],
            ["Not supported at this level.", "Not supported at this level.",
             "Not supported at this level.", "Not supported at this level."], tags);
}
