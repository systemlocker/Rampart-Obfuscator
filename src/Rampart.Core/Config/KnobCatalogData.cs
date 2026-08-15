namespace Rampart.Config;

/// <summary>The full knob catalog: one entry per tunable option, ordered the same
/// way <see cref="KnobGroups.All"/> walks the dashboard (static reading first,
/// live analysis last). Ids are stable CLI identifiers — other code (presets,
/// concern rules, templates) references them by literal, so never rename.</summary>
public static class KnobCatalogData
{
    // Points calibration (Light/Balanced/Heavy/Maximum):
    //  - Static transforms are cheap (1-2); VM and "nuclear" options are
    //    expensive (4-8 at Heavy/Maximum) — one strong knob at Heavy must read
    //    as a small fraction of the public 20-point single-knob ceiling.
    //  - A `--preset balanced` build (which presets clamp the six deliberate-
    //    use-only knobs to Off, see Presets.PresetMap) lands at 62 points:
    //    cheap knobs carry 1, heavier mechanisms 2-3 at Balanced.
    //  - Values are non-decreasing per knob: raising a level never gets cheaper.
    public static readonly IEnumerable<KnobDef> Entries =
    [
        // ------------------------------------------------------------------ packaging
        new("packaging.symbol-scrub", KnobGroups.Packaging, "Symbol scrub",
            "Strips the debug directory, PDB path strings, Rich header, section names, and build timestamps.",
            [1, 1, 1, 2],
            [
                "Strips the debug directory and any embedded PDB path from the image.",
                "Also zeroes the Rich header and blanks section names in the section table.",
                "Also zeroes timestamp fields across the headers (TimeDateStamp and the export/import table clocks).",
                "Re-scans for leftovers: debug-referencing data directories and COFF symbol table remnants are zeroed too.",
            ],
            [ThreatTags.Static]),

        new("packaging.import-concealment", KnobGroups.Packaging, "Import concealment",
            "Rebuilds imports as a hash-resolved on-demand table and destroys the classic IAT.",
            [1, 2, 2, 3],
            [
                "Moves the core module imports into a build-time table resolved by hash at startup.",
                "Adds the remaining imports; the classic IAT is zeroed once the stub has resolved names by hash.",
                "Resolution goes lazy: imports resolve on first call and the stale resolution data is wiped as it is used.",
                "Every import resolves through the hashed table with per-build hash seeds and decoy entries mixed in.",
            ],
            [ThreatTags.Static, ThreatTags.Dump]),

        new("packaging.header-disguise", KnobGroups.Packaging, "Header disguise",
            "Rewrites TimeDateStamp and linker metadata with plausible decoys instead of build truth.",
            [1, 1, 2, 2],
            [
                "Rewrites TimeDateStamp to a plausible random value instead of the real build time.",
                "Adds a decoy PDB path pointing at a fake project so analysts chase a dead end.",
                "Adds a decoy linker version and machine/subsystem-consistent header fields.",
                "Full decoy profile: consistent timestamps, versions, and checksum so the image reads as ordinary toolchain output.",
            ],
            [ThreatTags.Static]),

        new("packaging.ep-confusion", KnobGroups.Packaging, "Entry-point confusion",
            "Routes the entry point through a runtime stub with overlapping bytes before the real OEP.",
            [1, 1, 3, 4],
            [
                "The entry point routes through a runtime stub that computes the real OEP address before jumping.",
                "Adds overlapping instructions at the transition so linear disassembly desynchronizes.",
                "Adds misaligned, interleaved computation before OEP so the stub reads as garbage when traced naively.",
                "Adds multiple bogus entry candidates and stack-pivot noise; only one path reaches OEP.",
            ],
            [ThreatTags.Static, ThreatTags.Dump]),

        new("packaging.packer", KnobGroups.Packaging, "Section packer",
            "Compresses sections behind a tiny LZSS-family runtime decompression stub.",
            [2, 3, 5, 7],
            [
                "Compresses the main sections behind a runtime decompression stub.",
                "Raises compression and packs more sections; the decoder stays deliberately tiny.",
                "Compresses nearly all sections (LZSS-family codec) and reshapes the section layout to hide original boundaries.",
                "Full-image LZSS-family compression; headers and layout are rebuilt around the packed data.",
            ],
            [ThreatTags.Static, ThreatTags.Dump]),

        // ------------------------------------------------------ string-protection
        new("strings.encryption", KnobGroups.StringProtection, "Layered string encryption",
            "Encrypts every covered string literal in place; a startup stub decrypts by layers before the entry point.",
            [1, 1, 2, 3],
            [
                "Baseline layer: per-string XOR keys with a build seed, applied to referenced ASCII/UTF-16 runs.",
                "Adds a rolling algebraic layer per string (key evolves per byte) so no two offsets share a transform.",
                "Adds a post-read scrub: decrypted buffers re-encrypt when the wait window fires.",
                "Adds per-site polymorphism — each site gets an independently generated decrypt sequence and key schedule.",
            ],
            [ThreatTags.Static]),

        new("strings.anti-instrumentation", KnobGroups.StringProtection, "String anti-instrumentation",
            "Traps breakpoint instrumentation landing on string materialization sites.",
            [1, 2, 2, 2],
            [
                "INT 3 sentinel bytes around decrypt sites: a debugger single-stepping them drifts the result.",
                "Adds an INT 2D probe before decrypt blocks — attached debuggers take the wrong path length.",
                "Adds hardware-breakpoint register checks at decrypt time; a hit silently returns garbage bytes.",
                "All probes feed the silent-taint path instead of branching: instrumented reads decrypt to noise.",
            ],
            [ThreatTags.Debug, ThreatTags.Tools]),

        new("strings.coverage", KnobGroups.StringProtection, "Coverage tuning",
            "Chooses which strings get protected, saving build size when most strings are noise.",
            [0, 0, 0, 0],
            [
                "Protects referenced strings of 6+ bytes in read-only data sections.",
                "Raises the floor to 8+ bytes and skips strings that only feed the export/debug tables.",
                "Adds a per-section coverage ratio cap so huge resource-like data blocks stay out.",
                "Protects everything decodable, including short strings in initialized data sections.",
            ],
            [ThreatTags.Static]),

        // ------------------------------------------------------- code-transformation
        new("code-transformation.junk-insertion", KnobGroups.CodeTransformation, "Junk insertion",
            "Inserts meaningful-noise instructions and unreachable decoy branches into function bodies.",
            [1, 1, 2, 3],
            [
                "Inserts meaningful-noise instructions (flag-preserving computations, dead stores) between real ones.",
                "Adds unreachable decoy branches so control flow looks richer than it is.",
                "Raises junk density and varies instruction encodings so no two builds share filler bytes.",
                "Full coverage: every basic block carries noise and multiple decoy paths.",
            ],
            [ThreatTags.Static]),

        new("code-transformation.mba-constants", KnobGroups.CodeTransformation, "MBA constants",
            "Splits literal constants through per-build boolean and mixed-arithmetic identities.",
            [1, 1, 2, 2],
            [
                "XOR-splits constants in Rampart-generated runtime stubs; target-code rewriting remains planned.",
                "Extends two-term identities to eligible target-code constants after verified lifting.",
                "Uses deeper multi-term identities so reconstructed values need real symbolic solving.",
                "Per-build identity selection with nested rewrites; recovering one constant means solving its whole chain.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("code-transformation.per-build-mutation", KnobGroups.CodeTransformation, "Per-build mutation",
            "Re-randomizes layout, keys, and opcode encodings so every build ships different bytes.",
            [1, 1, 2, 3],
            [
                "Randomizes layout offsets and register allocation per build seed.",
                "Also varies opcode encodings (equivalent instruction forms) per build.",
                "Also rotates keys, junk seeds, and stub layouts; no two builds share byte patterns.",
                "Every mutable dimension is re-rolled: layout, encodings, keys, decoys, and stub internals.",
            ],
            [ThreatTags.Static]),

        new("code-transformation.flattening", KnobGroups.CodeTransformation, "Control-flow flattening",
            "Restructures verified functions around a state-machine dispatch loop.",
            [1, 2, 4, 5],
            [
                "Restructures a small set of verified functions around a state-variable dispatch loop.",
                "Extends flattening to most verified functions; state transitions are computed, not compared.",
                "All verified functions are flattened and dispatch order is scrambled per build.",
                "Flattens everything liftable and intermixes the dispatcher states of neighboring functions.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        // ---------------------------------------------------------------- anti-debug
        new("anti-debug.channel-sweep", KnobGroups.AntiDebug, "Debug channel sweep",
            "Sweeps nine debugger detection channels on a configurable interval.",
            [1, 2, 3, 4],
            [
                // Channel counts are contractual: Light=3, Balanced=6, Heavy=9; Maximum
                // keeps nine channels and spends its budget on cadence and coupling.
                "Checks three channels: IsDebuggerPresent, PEB.BeingDebugged, and CheckRemoteDebuggerPresent.",
                "Adds three more: NtQueryInformationProcess (debug port/object), PEB.NtGlobalFlag, and heap flags.",
                "Adds the final three: RDTSC drift timing, INT 2D/INT 3 traps, and the DR-register sweep.",
                "Same nine channels on a faster sweep interval, with results fed into the response layer.",
            ],
            [ThreatTags.Debug]),

        new("anti-debug.inline-hook-check", KnobGroups.AntiDebug, "Inline hook check",
            "Hashes prologue bytes of critical ntdll exports to catch inline hook patches.",
            [1, 1, 2, 3],
            [
                "Hashes the prologue bytes of the most-hooked ntdll exports and verifies them at startup.",
                "Extends coverage to the full hot-export set and re-verifies periodically.",
                "Adds full-function span checks so mid-function hook engines are caught too.",
                "Continuous verification with per-build hash salts; any mismatch feeds the response layer.",
            ],
            [ThreatTags.Debug, ThreatTags.Tools]),

        new("anti-debug.veh-tamper", KnobGroups.AntiDebug, "VEH tamper check",
            "Walks and verifies the vectored exception handler chain for tampering.",
            [1, 1, 2, 2],
            [
                "Installs a VEH and verifies at startup that its own entry still sits in the chain.",
                "Periodically walks the full vectored handler chain looking for foreign or reordered entries.",
                "Verifies handler code integrity, not just presence; patches to registered handlers are flagged.",
                "Continuous chain walk cross-checked against the TLS sentinel records.",
            ],
            [ThreatTags.Debug]),

        new("anti-debug.dll-notify", KnobGroups.AntiDebug, "Load notifications",
            "Registers an LDR notification callback to observe every module load, including manual maps.",
            [1, 1, 2, 2],
            [
                "Registers an LDR notification callback so every DLL load into the process is observed.",
                "Flags known analysis module names and load-time anomalies (wrong size, no file backing).",
                "Flags manual-map-adjacent loads: mapped images that never produced an LDR event.",
                "Flagged loads feed the response layer immediately instead of only being logged.",
            ],
            [ThreatTags.Inject, ThreatTags.Tools]),

        // --------------------------------------------------------------- anti-inject
        new("anti-inject.dacl-hardening", KnobGroups.AntiInject, "DACL hardening",
            "Applies a DACL denying PROCESS_VM_WRITE and PROCESS_CREATE_THREAD to non-SYSTEM SIDs.",
            [1, 1, 2, 2],
            [
                "Applies a DACL denying PROCESS_VM_WRITE to non-SYSTEM SIDs.",
                "Also denies PROCESS_CREATE_THREAD and asserts the ACL on both process and thread handles.",
                "Also restricts PROCESS_VM_READ for non-owners, closing dumper handles as a side effect.",
                "Re-asserts the DACL periodically so handle-duplication races cannot stick.",
            ],
            [ThreatTags.Inject]),

        new("anti-inject.cet-shadow-stack", KnobGroups.AntiInject, "CET shadow stack",
            "Enables and verifies CET shadow stack; ROP attempts fault into the VEH layer.",
            [1, 1, 3, 4],
            [
                "Enables CET shadow stack where the OS and CPU support it; unsupported systems run unchanged.",
                "Adds a startup verification pass proving the shadow stack is actually active.",
                "Shadow-stack mismatches (ROP) fault into our VEH and count as detection events.",
                "Continuous enforcement checks wired into the response layer; policy loss is itself a detection.",
            ],
            [ThreatTags.Inject, ThreatTags.Kernel]),

        new("anti-inject.dynamic-code-policy", KnobGroups.AntiInject, "Dynamic code policy",
            "Applies ProcessDynamicCodePolicy so RWX allocations are refused.",
            [1, 2, 2, 3],
            [
                "Applies ProcessDynamicCodePolicy so new RWX allocations fail.",
                "Extends the policy to child processes the binary spawns.",
                "Adds explicit checks that no RWX pages exist and thread contexts are not marked for dynamic code.",
                "Verifies the policy survived loader initialization; any RWX page is reported and neutralized.",
            ],
            [ThreatTags.Inject]),

        new("anti-inject.iat-hash-check", KnobGroups.AntiInject, "Import hash check",
            "Re-verifies hot ntdll import targets by hash at call time; trampolines trip the check.",
            [1, 1, 2, 3],
            [
                "Hashes the hot ntdll import targets at load and verifies them before first use.",
                "Re-verifies at call time through the concealed import layer, so trampolines outside .text trip it.",
                "Covers the full import set and verifies whole function spans, not just prologues.",
                "Per-build hash salts plus cross-verification against pristine copies held in protector data.",
            ],
            [ThreatTags.Inject, ThreatTags.Tools]),

        // ------------------------------------------------------------- anti-sandbox
        new("anti-sandbox.virtualisation-detect", KnobGroups.AntiSandbox, "Virtualisation detect",
            "Detects hypervisors via CPUID, timing signatures, and VM artifacts.",
            [1, 1, 2, 2],
            [
                "Reads the CPUID hypervisor bit and cross-checks the reported vendor string.",
                "Adds timing signatures: tick calibration and overhead patterns consistent with a VM.",
                "Adds VM artifact scanning: registry keys, devices, and MAC prefixes of common hypervisors.",
                "Combines all channels with per-build thresholds; the verdict feeds the response layer.",
            ],
            [ThreatTags.Sandbox]),

        new("anti-sandbox.fingerprint-suite", KnobGroups.AntiSandbox, "Sandbox fingerprints",
            "Fingerprints known analysis services and sandbox families; each level adds families.",
            [1, 1, 2, 3],
            [
                "Matches artifacts of the common open-source sandbox family (default paths, drivers, hostnames).",
                "Adds fingerprints for interactive browser-run analysis services (agents, environment quirks).",
                "Adds hardware-assisted and enterprise analysis platforms (hypervisor hooks, instrumentation drivers).",
                "Adds heuristics for unnamed sandboxes: environment inconsistency and execution-speed scoring on top of all families.",
            ],
            [ThreatTags.Sandbox, ThreatTags.Tools]),

        new("anti-sandbox.human-gate", KnobGroups.AntiSandbox, "Human activity gate",
            "Requires recent human input activity and detects fast-forwarded sleep timelines.",
            [1, 1, 2, 2],
            [
                "Sensitive paths require a recent input event (keyboard/mouse) within a generous window.",
                "Tightens the window and adds fast-forward detection: skipped sleeps inconsistent with the wall clock.",
                "Adds input plausibility checks (event spacing, device presence) against synthetic input injection.",
                "Continuous gating: sensitive operations re-check activity and verdicts feed the response layer.",
            ],
            [ThreatTags.Sandbox]),

        // --------------------------------------------------------- analysis-crashers
        new("analysis.ida-bomb", KnobGroups.AnalysisCrashers, "Autoanalysis bomb",
            "Floods static analysis with synthetic prologues and cross-references.",
            [1, 2, 4, 6],
            [
                "Seeds the image with a few hundred synthetic function prologues for auto-analysis to chew on.",
                "Adds synthetic cross-references weaving the decoy heads into a fake call graph.",
                "Scale jumps to tens of thousands of fake function heads with plausible prologue variety.",
                "Full flood: decoy heads, cross-references, and fake unwind data saturate the indexer.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("analysis.hexrays-denial", KnobGroups.AnalysisCrashers, "Decompiler denial",
            "Injects decompiler-hostile constructs that break deoptimization passes.",
            [1, 1, 3, 4],
            [
                "Injects constructs known to decompile poorly (pointer aliasing games, jump-table lookalikes) into cold code.",
                "Adds pattern dead ends: expressions that collapse wrongly under common simplifier rules.",
                "Adds microcode-hostile sandwiches: constructs that break decompiler passes when analyzed in sequence.",
                "Denial constructs spread through real and decoy code alike; every function decompiles to noise.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("analysis.symbolic-denial", KnobGroups.AnalysisCrashers, "Symbolic denial",
            "Plants concolic time-bombs and constraint-pathology gadgets in decoy bodies.",
            [1, 1, 3, 4],
            [
                "Plants concolic time-bombs in decoy bodies: paths whose solver time explodes when reached.",
                "Adds constraint-pathology gadgets (nested XOR chains, mixed-width arithmetic) around decoy branches.",
                "Densifies the gadgets and links them so backing out of one path re-triggers the pathology.",
                "Decoy bodies become solver tar pits: every reachable-looking path multiplies constraints.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("analysis.static-decode-denial", KnobGroups.AnalysisCrashers, "Static decode denial",
            "Overlaps instructions and encrypts the code section on disk (AES-128-CTR at Heavy).",
            [1, 2, 4, 6],
            [
                "Overlaps instructions in cold regions so linear and recursive disassembly disagree.",
                "Extends overlapping decode across all non-entry code regions.",
                "Encrypts the code section on disk with AES-128-CTR; only the runtime stub holds the key schedule.",
                "Adds page-mode: the section stays encrypted even in memory and only the executing page turns plaintext.",
            ],
            [ThreatTags.Static]),

        new("analysis.runtime-header-corruption", KnobGroups.AnalysisCrashers, "Runtime header corruption",
            "Scrubs DOS/PE headers in memory once the loader has finished with them.",
            [1, 1, 2, 2],
            [
                "Scrubs the DOS and PE signature fields in memory once the loader is finished with them.",
                "Also invalidates the in-memory section table so memory scanners lose their map.",
                "Scrubbed fields are trapped: toolhelp/psapi-style snapshots return inconsistent values.",
                "Headers are re-scrubbed after every loader event (late DLL load, resource access).",
            ],
            [ThreatTags.Dump]),

        // -------------------------------------------------------- memory-protection
        new("memory.anti-dump", KnobGroups.MemoryProtection, "Anti-dump",
            "Corrupts in-memory section headers and traps VirtualQuery to break dump reconstruction.",
            [2, 2, 4, 5],
            [
                "Corrupts in-memory section headers so reconstruction tools rebuild a broken image.",
                "Adds VirtualQuery traps: region metadata lies about sizes and protections.",
                "Combines header corruption with fake regions so dumpers carve out decoy data.",
                "Every dump path addressed: headers, region map, and copy-on-write bait all disagree.",
            ],
            [ThreatTags.Dump]),

        new("memory.at-rest-encryption", KnobGroups.MemoryProtection, "At-rest encryption",
            "Holds heap, TLS, and dormant data encrypted under rotating keys.",
            [1, 1, 3, 4],
            [
                "Holds dormant data (unused strings, config blobs) encrypted until first access.",
                "Adds heap allocations holding sensitive data under key, decrypted per access.",
                "Rotates keys per region on a schedule and wipes stale key material.",
                "TLS slots, dormant code paths, and all heap data rotate continuously under distinct keys.",
            ],
            [ThreatTags.Dump]),

        new("memory.api-concealment", KnobGroups.MemoryProtection, "API concealment",
            "Routes API calls through protector-owned wrappers instead of direct imports.",
            [1, 1, 2, 3],
            [
                "Routes sensitive API calls through protector-owned wrapper thunks.",
                "Extends routing to most imports; wrappers live in per-build generated code.",
                "Wrappers migrate per build and per run; call sites never touch the same thunk twice.",
                "Full coverage with call-site spoofing: wrapper frames mimic ordinary local calls.",
            ],
            [ThreatTags.Static, ThreatTags.Dump]),

        new("memory.stack-spoof", KnobGroups.MemoryProtection, "Stack spoofing",
            "Falsifies return-address chains so stack walkers misread call stacks.",
            [1, 1, 2, 3],
            [
                "Falsifies the top return addresses during sensitive calls so stack walkers misread.",
                "Builds plausible fake frames several levels deep with consistent module references.",
                "Spoofed chains are made consistent with the falsified region map so cross-checks agree.",
                "Every sensitive call runs on a spoofed chain tuned against common walker implementations.",
            ],
            [ThreatTags.Dump, ThreatTags.Debug]),

        new("memory.page-mode-decrypt", KnobGroups.MemoryProtection, "Page-mode decryption",
            "Keeps only the executing page of protected code plaintext.",
            [1, 2, 4, 6],
            [
                "Only the executing page of protected code stays plaintext; neighbor pages stay encrypted.",
                "Adds per-page key separation so decrypting one page yields nothing about the next.",
                "Adds eviction: pages re-encrypt as soon as execution leaves them.",
                "Single-page window with fault-driven decrypt; at no instant are two protected pages plaintext.",
            ],
            [ThreatTags.Dump, ThreatTags.Static]),

        new("memory.sleep-mask", KnobGroups.MemoryProtection, "Sleep mask",
            "Re-encrypts decrypted regions while the process waits in sleep calls.",
            [1, 1, 3, 4],
            [
                "While the process waits, decrypted regions are re-encrypted for the duration of the sleep.",
                "Adds import and TLS slot masking during the same wait windows.",
                "Wait cycles rotate the mask keys so consecutive dumps share nothing.",
                "All sensitive memory is masked during any wait, including short yields.",
            ],
            [ThreatTags.Dump]),

        // ------------------------------------------------------------ virtualization
        new("virtualization.per-build-isa", KnobGroups.Virtualization, "Per-build ISA",
            "Generates a fresh VM instruction set (opcodes, operands, registers) per build.",
            [1, 2, 4, 6],
            [
                "Generates a fresh opcode permutation for the build's VM bytecode.",
                "Also varies operand encodings so decoding tables cannot be reused across builds.",
                "Adds per-build register mapping and encoding interlocks (ops whose meaning depends on page).",
                "Every ISA dimension is re-rolled per build: opcodes, operands, registers, and layout.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("virtualization.coverage", KnobGroups.Virtualization, "VM coverage",
            "Controls how aggressively the lifter converts functions to per-build bytecode.",
            [1, 2, 4, 6],
            [
                "Lifts a small set of verified functions into per-build bytecode; the rest stays native.",
                "Lifts the main logic functions; unsupported constructs always fall back to native.",
                "Lifts most liftable functions including hot inner loops.",
                "Lifts every function the lifter can verify; nothing verifiable stays native.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("virtualization.extended-isa", KnobGroups.Virtualization, "Extended ISA",
            "Opt-in wider lifter support: SIMD subsets, string ops, and atomics when verified.",
            [1, 1, 3, 4],
            [
                "Adds verified subsets of common SIMD operations to the lifter when semantics check out.",
                "Adds string operations (scan/compare/copy families) with full semantic verification.",
                "Adds atomics (lock-prefixed and interlocked families) with concurrency verification.",
                "Full opt-in set — SIMD, string, atomics, and rare encodings — each still gated on verification.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("virtualization.handler-polymorphism", KnobGroups.Virtualization, "Handler polymorphism",
            "VM handlers differ per build and per call site; no shared handler bodies.",
            [1, 1, 3, 4],
            [
                "VM handlers get per-build bodies; each build implements its ISA differently.",
                "Handlers also differ per call site within one build.",
                "Adds semantic-equivalent rewrites so identical handlers share no instruction patterns.",
                "Every handler instance is unique; no two dispatches execute the same bytes.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("virtualization.vm-nesting", KnobGroups.Virtualization, "VM nesting",
            "Runs critical bytecode under a second VM with a disjoint instruction set.",
            [1, 1, 4, 6],
            [
                // The second VM only earns its cost from Heavy on; Light/Balanced grow a small
                // pilot so the step to Heavy is a size change, not a new mechanism appearing.
                "Prepares the nesting scaffold: one critical function runs under a second-level VM pilot.",
                "Grows the pilot: several critical functions run nested under the second VM.",
                "The second VM gets a fully disjoint ISA; critical bytecode no longer shares primitives with level one.",
                "Deep nesting on all critical paths; the two levels cross-verify each other's bytecode integrity.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("virtualization.jit-handlers", KnobGroups.Virtualization, "JIT handler decryption",
            "Handler bodies decrypt only for the instant they execute.",
            [1, 1, 4, 5],
            [
                "Handler bodies are stored encrypted; the dispatch loop decrypts before executing.",
                "Handlers decrypt in place with per-page keys and re-encrypt after execution.",
                "Only the executing handler is plaintext — decrypt on dispatch, wipe on return.",
                "Instant-window decryption: handler pages exist as plaintext only for the executing window.",
            ],
            [ThreatTags.Dump, ThreatTags.Tools]),

        new("virtualization.runtime-rekey", KnobGroups.Virtualization, "Runtime re-keying",
            "Moves and re-keys bytecode regions continuously while the process runs.",
            [1, 1, 3, 4],
            [
                "Bytecode regions relocate once shortly after startup.",
                "Adds periodic re-keying: bytecode moves and old locations are wiped.",
                "Re-keying becomes continuous and event-driven (timer plus detection signals).",
                "Constant churn: bytecode never rests at one address or under one key for long.",
            ],
            [ThreatTags.Dump, ThreatTags.Static]),

        new("virtualization.decoy-bodies", KnobGroups.Virtualization, "Decoy bodies",
            "Fills stripped function slots with plausible decoy code.",
            [1, 1, 2, 2],
            [
                "Fills stripped native slots with plausible decoy code matching the original shape.",
                "Decoys carry realistic constants and call patterns borrowed from the build's real functions.",
                "Decoys become interactive: reachable edges execute and produce plausible results.",
                "Decoy density matches real code across the image; lifted functions hide in the crowd.",
            ],
            [ThreatTags.Static]),

        // --------------------------------------------------------- integrity-binding
        new("integrity.kernel-wall", KnobGroups.IntegrityBinding, "Kernel wall",
            "Sentinel probes plus the mitigation foundation the integrity layers chain from.",
            [1, 1, 3, 4],
            [
                "Deploys the first sentinel load probes and verifies their integrity at startup.",
                "Adds more probes on a schedule; missing or altered sentinels mark the session.",
                "Sentinel coverage spans all critical regions; probes vary per build and per run.",
                "The full mitigation foundation is armed and every probe feeds the runtime key material.",
            ],
            [ThreatTags.Kernel, ThreatTags.Dump]),

        new("integrity.measurement-channels", KnobGroups.IntegrityBinding, "Measurement channels",
            "Folds PE, sentinel, per-function, and live code-hash measurements into the runtime key.",
            [1, 1, 2, 4],
            [
                // Channel counts are contractual: one channel per level, Light=1 .. Maximum=4.
                "Folds one channel into the runtime key: the PE fingerprint.",
                "Adds a second channel: sentinel probe status joins the key derivation.",
                "Adds a third channel: per-function tags verified before each protected function runs.",
                "Adds the fourth channel: a live code-hash chain over executing code, checked continuously.",
            ],
            [ThreatTags.Static, ThreatTags.Kernel]),

        new("integrity.self-debug-port", KnobGroups.IntegrityBinding, "Self debug port",
            "The process owns its debug port so external debuggers cannot attach.",
            [1, 2, 4, 5],
            [
                // Tiers follow the hold -> consumer -> retake ladder; Maximum adds fail-closed behavior.
                "Hold tier: the process holds its own debug object so external debuggers cannot attach.",
                "Consumer tier: debug events are drained and interpreted by our own code.",
                "Retake tier: if the port is stolen, ownership is re-asserted and the session tainted.",
                "Full ownership with fail-closed behavior: losing the port silently diverges execution.",
            ],
            [ThreatTags.Debug, ThreatTags.Dump]),

        new("integrity.tls-veh-ownership", KnobGroups.IntegrityBinding, "TLS/VEH ownership",
            "Chains sentinels across TLS callbacks and the VEH chain with cross-verification.",
            [1, 1, 2, 3],
            [
                "Sentinels chain across TLS callbacks; removal of our callback marks the session.",
                "Adds VEH chain sentinels that cross-verify the TLS records.",
                "TLS and VEH sentinels re-verify each other continuously, in both directions.",
                "Full mesh: every TLS callback and VEH entry validates its peers' integrity records.",
            ],
            [ThreatTags.Debug, ThreatTags.Tools]),

        new("integrity.header-scrub", KnobGroups.IntegrityBinding, "Runtime header scrub",
            "Zeroes section table, NumberOfSections, MZ magic, and e_lfanew in memory.",
            [1, 1, 2, 2],
            [
                "Zeroes the in-memory section table after loader initialization.",
                "Also zeroes NumberOfSections and the timestamp fields the loader no longer needs.",
                "Also clears the MZ magic and e_lfanew so in-memory parsers find no image header at all.",
                "Full scrub re-armed after every loader event; nothing reconstructs the header map.",
            ],
            [ThreatTags.Dump]),

        new("integrity.hidden-threads", KnobGroups.IntegrityBinding, "Hidden threads",
            "Runs worker threads under the hide-from-debugger flag.",
            [1, 1, 2, 2],
            [
                "Worker threads set the hide-from-debugger flag so debuggers never list them.",
                "Adds more hidden workers for the sweep and measurement loops.",
                "Hidden threads verify each other's state; a listed or dead worker marks the session.",
                "All protector threads hidden, cross-verified, and respawned on tamper.",
            ],
            [ThreatTags.Debug, ThreatTags.Tools]),

        new("integrity.loader-hijack", KnobGroups.IntegrityBinding, "Loader entry interposition",
            "Interposes on loader entry validation so injector load paths get refused.",
            [1, 2, 3, 4],
            [
                "Interposes on the loader's DLL-entry validation path for the protected modules.",
                "Poisons the validator state so foreign inject paths get refused outright.",
                "Covers the LdrLoadDll and init-routine paths with per-build interposition.",
                "Full interposition re-asserted periodically; interposition that vanishes is re-installed.",
            ],
            [ThreatTags.Inject]),

        new("integrity.mitigation-stack", KnobGroups.IntegrityBinding, "Mitigation stack",
            "Wires ASLR, DEP, CFG, CET, image-load, and dynamic-code mitigation policies.",
            [1, 1, 2, 3],
            [
                "Wires ASLR, DEP, and CFG mitigations for the process and its threads.",
                "Adds CET (where available) and image-load policies.",
                "Adds dynamic-code policy coupling and strict handle rules.",
                "The full stack — ASLR/DEP/CFG/CET/image-load/dynamic-code — is asserted and re-verified.",
            ],
            [ThreatTags.Inject, ThreatTags.Kernel]),

        // -------------------------------------------------------------------- response
        new("response.silent-taint", KnobGroups.Response, "Silent taint",
            "Taints the session key on detection so execution diverges with no branch to NOP.",
            [1, 1, 2, 3],
            [
                "On first detection, taints the session key so later results quietly diverge.",
                "Adds delayed, varied divergence points so the cause is not localizable.",
                "Multiple taint stages interact; every detection shifts all downstream behavior.",
                "Full divergence engineering: no branch to NOP and no single patch restores correct behavior.",
            ],
            [ThreatTags.Debug, ThreatTags.Tools]),

        new("nuclear.nanomites", KnobGroups.Response, "Nanomites",
            "Converts conditional branches to INT 3 resolved by the VEH at runtime.",
            [2, 3, 5, 7],
            [
                // Deliberate-use only: presets keep every nuclear.* knob Off (see Presets.PresetMap)
                // because some tooling flags their patterns; points stay high accordingly.
                "Converts a first slice of conditional branches to INT 3, resolved by our VEH at runtime.",
                "Extends conversion to most verifiable branches; handler tables are per-build.",
                "Nearly all conditional branches become nanomites; INT 3 without our VEH is fatal.",
                "Everything convertible plus decoy INT 3s; breakpoint tampering diverges execution.",
            ],
            [ThreatTags.Static, ThreatTags.Debug, ThreatTags.Tools]),

        new("nuclear.exception-flow", KnobGroups.Response, "Exception flow",
            "Routes control flow through structured exceptions instead of branches.",
            [2, 3, 5, 6],
            [
                "Routes selected control flow through structured exceptions instead of branches.",
                "Extends exception routing to interleaved paths; handlers compute the next target.",
                "Adds exception-based loops and data flow so linear tracing loses the thread.",
                "Control flow is fully exception-driven; static call graphs and traces disagree with reality.",
            ],
            [ThreatTags.Static, ThreatTags.Tools]),

        new("response.tool-response", KnobGroups.Response, "Tool response",
            "Fires a configured response (exit/crash/misdirect) when analysis tools are detected.",
            [1, 1, 3, 4],
            [
                "On detecting named analysis tools (debuggers, memory editors, sandboxes), fires the configured response — default: clean exit.",
                "Adds crash and misdirect responses, chosen per tool class.",
                "Adds per-tool responses with multi-stage misdirection before termination.",
                "Adds corrupt-exports retaliation: the detected tool's own process is fed poisoned data.",
            ],
            [ThreatTags.Tools, ThreatTags.Sandbox]),

        new("nuclear.memory-ambush", KnobGroups.Response, "Memory ambush",
            "Decoy regions, rotating import slots, and INT 3 walls in scorched memory.",
            [2, 3, 5, 7],
            [
                "Plants decoy regions in memory that flag scanners which touch them.",
                "Adds rotating import slots so patching a resolved target buys nothing.",
                "Adds INT 3 walls around the scorched regions; stray execution traps into our VEH.",
                "Full ambush: decoys, rotating slots, and trap walls re-armed continuously.",
            ],
            [ThreatTags.Dump, ThreatTags.Tools]),

        new("nuclear.injection-hunter", KnobGroups.Response, "Injection hunter",
            "Monitors for foreign loads, poisons manual maps, and blocks APC injection.",
            [1, 2, 4, 5],
            [
                "Monitors for foreign module loads into the process and flags them.",
                "Adds manual-map countermeasures: section poison makes map-and-run fail loudly.",
                "Adds APC injection blocking: user APCs queued from foreign sources are refused.",
                "Full hunter: monitor, poison, and blocker cooperate and feed the response layer.",
            ],
            [ThreatTags.Inject]),

        new("response.brand-overlay", KnobGroups.Response, "Owner watermark",
            "Embeds an owner watermark and build stamp in the protected image.",
            [1, 1, 1, 1],
            [
                "Embeds an owner watermark stamp in a build-specific location.",
                "Adds a build timestamp and seed-derived suffix to the stamp.",
                "Weaves the stamp into decoy bodies so removal costs real analysis time.",
                "The stamp is validated by the integrity chain; tampering with it diverges execution.",
            ],
            [ThreatTags.Static]),

        new("response.custom-messages", KnobGroups.Response, "Custom messages",
            "Carries your custom tamper and detection message payloads.",
            [1, 1, 1, 1],
            [
                "Emits your custom message body on tamper detection.",
                "Adds per-event message variants (tamper versus tool detection).",
                "Adds decoy message triggers so the real notices hide in noise.",
                "Messages are signed and bound to the build; forged notices count as detections themselves.",
            ],
            [ThreatTags.Static]),
    ];
}
