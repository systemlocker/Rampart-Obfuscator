using System.Buffers.Binary;
using System.Text;
using Rampart.Config;
using Rampart.Pe;
using Rampart.X64;

namespace Rampart.Engine.Passes;

/// <summary>Low-level Windows hardening and integrity checks. The pass has two
/// phases because its monitor must be emitted before the entry dispatcher freezes
/// the init chain, then installed as the outermost TLS callback afterwards.</summary>
public sealed class RuntimeHardeningPass
{
    private const string DaclHardening = "anti-inject.dacl-hardening";
    private const string CetShadowStack = "anti-inject.cet-shadow-stack";
    private const string DynamicCodePolicy = "anti-inject.dynamic-code-policy";
    private const string IatHashCheck = "anti-inject.iat-hash-check";
    private const string KernelWall = "integrity.kernel-wall";
    private const string MeasurementChannels = "integrity.measurement-channels";
    private const string TlsVehOwnership = "integrity.tls-veh-ownership";
    private const string MitigationStack = "integrity.mitigation-stack";
    private const string SilentTaint = "response.silent-taint";
    private const string ToolResponse = "response.tool-response";
    private const string BrandOverlay = "response.brand-overlay";
    private const string CustomMessages = "response.custom-messages";

    private const ulong FnvOffsetBasis = 14695981039346656037UL;
    private const ulong FnvPrime = 1099511628211UL;
    private const int MaximumMetadataBytes = 64 * 1024;
    private const ushort ImageFileRelocsStripped = 0x0001;
    // Allow SYSTEM full control; explicitly deny Everyone tampering/injection rights
    // (TERMINATE | CREATE_THREAD | VM_OPERATION | VM_READ | VM_WRITE | DUP_HANDLE |
    // CREATE_PROCESS | SUSPEND_RESUME | DELETE | WRITE_DAC | WRITE_OWNER = 0x000D08FB);
    // allow Everyone only SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION (0x00101000).
    internal const string ProcessDaclSddl = "D:P(A;;GA;;;SY)(D;;0x000D08FB;;;WD)(A;;0x00101000;;;WD)";

    private BuildContext? _context;
    private uint _monitorRva;
    private uint _tlsCallbackRva;
    private uint _latchRva;
    private bool _hasMonitor;
    private bool _postPhaseComplete;
    private bool _postStringResponseRegistered;
    private RuntimeDetectionStateLayout? _state;
    private IReadOnlyDictionary<string, uint>? _iat;
    private bool _silentTaint;
    private bool _toolResponse;
    private bool _customMessage;
    private ulong _taintConstant;

    /// <summary>Applies image metadata, emits response records, and builds the
    /// runtime monitor. Call after code/string/import rewriting and immediately
    /// before EntryPointPass.</summary>
    public void RunBeforeEntryPoint(BuildContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        if (_context is not null)
            throw new InvalidOperationException("A RuntimeHardeningPass instance can protect only one image.");
        _context = ctx;

        bool dacl = Enabled(ctx, DaclHardening);
        bool cet = Enabled(ctx, CetShadowStack);
        bool dynamicCode = Enabled(ctx, DynamicCodePolicy);
        bool iatHash = Enabled(ctx, IatHashCheck);
        bool kernelWall = Enabled(ctx, KernelWall);
        bool measurement = Enabled(ctx, MeasurementChannels);
        bool tlsOwnership = Enabled(ctx, TlsVehOwnership);
        bool mitigation = Enabled(ctx, MitigationStack);
        bool silentTaint = Enabled(ctx, SilentTaint);
        bool toolResponse = Enabled(ctx, ToolResponse);
        bool brand = Enabled(ctx, BrandOverlay);
        bool customMessage = Enabled(ctx, CustomMessages);
        bool responseProbe = silentTaint || toolResponse || customMessage;
        bool guardCf = ctx.Pe.DllChars.HasFlag(DllCharacteristics.GuardCf);

        if (brand)
            EmitMetadata(ctx, "RMPBRND1", ctx.Settings.Watermark ?? $"build-{(ulong)ctx.Settings.Seed:X16}", BrandOverlay, "owner watermark");
        if (customMessage)
            EmitMetadata(ctx, "RMPMSG01", ctx.Settings.CustomMessage ?? "Application integrity check failed.", CustomMessages, "custom response message");

        RuntimeDetectionStateLayout? state = null;
        if (dacl || cet || dynamicCode || iatHash || kernelWall || measurement || tlsOwnership || mitigation
            || silentTaint || toolResponse || customMessage)
        {
            state = RuntimeDetectionState.Ensure(ctx);
        }

        if (mitigation)
        {
            DllCharacteristics before = ctx.Pe.DllChars;
            bool relocsStripped = (ctx.Pe.Characteristics & ImageFileRelocsStripped) != 0;
            DllCharacteristics toAdd = relocsStripped
                ? DllCharacteristics.NxCompatible
                : DllCharacteristics.DynamicBase | DllCharacteristics.HighEntropyVa | DllCharacteristics.NxCompatible;
            ctx.Pe.DllChars = before | toAdd;
            SetPolicyStatus(ctx, state!, 1UL << 2);
            ctx.Log.Add(new(MitigationStack, relocsStripped
                ? $"asserted PE DEP flag (0x{(ushort)before:X4} -> 0x{ctx.Pe.DllCharacteristicsRaw:X4}); skipped ASLR flags because IMAGE_FILE_RELOCS_STRIPPED is set"
                : $"asserted PE ASLR/high-entropy-VA/DEP flags (0x{(ushort)before:X4} -> 0x{ctx.Pe.DllCharacteristicsRaw:X4}); preserved existing CFG metadata"));
        }

        if (cet)
        {
            ExtendedDllCharacteristicsEditor.Add(ctx, ExtendedDllCharacteristicsEditor.CetCompatible);
            SetPolicyStatus(ctx, state!, 1UL << 3);
            ctx.Log.Add(new(CetShadowStack,
                "emitted IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS with CETCOMPAT for hardware shadow-stack enforcement where enabled by Windows"));
        }

        // Response knobs remain useful when selected alone: a small private
        // sentinel gives them a concrete tamper producer without silently
        // enabling a different catalog knob.
        bool needsMonitor = dacl || dynamicCode || iatHash || kernelWall || measurement || tlsOwnership || responseProbe;
        if (!needsMonitor)
            return;

        var iat = new Dictionary<string, uint>(StringComparer.Ordinal);
        var kernelApis = new List<string>();
        if (dynamicCode)
            kernelApis.Add("SetProcessMitigationPolicy");
        if (dacl)
            kernelApis.Add("LocalFree");
        if (customMessage)
            kernelApis.Add("OutputDebugStringA");
        if (toolResponse)
            kernelApis.Add("ExitProcess");
        if (kernelApis.Count > 0)
            Merge(iat, ImportDirectoryEditor.EnsureNamedImports(ctx, "KERNEL32.DLL", kernelApis.ToArray()));

        if (dacl)
        {
            Merge(iat, ImportDirectoryEditor.EnsureNamedImports(ctx, "ADVAPI32.DLL",
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                "GetSecurityDescriptorDacl",
                "SetSecurityInfo"));
        }

        List<CodeRange> codeRanges = measurement ? BuildStableCodeRanges(ctx) : [];
        ulong codeBasis = FnvOffsetBasis ^ (ulong)ctx.Settings.Seed;
        ulong codeHash = measurement ? HashCodeRanges(ctx.Pe, codeRanges, codeBasis) : 0;
        if (measurement)
        {
            RuntimeDetectionState.Enable(ctx, RuntimeDetectionKind.CodeModified);
            ctx.WriteData(state!.Rva + RuntimeDetectionStateLayout.CodeMeasurementOffset, BitConverter.GetBytes(codeHash));
        }
        if (iatHash)
            RuntimeDetectionState.Enable(ctx, RuntimeDetectionKind.IatModified);
        // Under Guard CF, Rampart avoids installing a new TLS callback entry, so
        // defer TLS callback ownership enforcement rather than raising false positives.
        bool checkTlsOwnership = tlsOwnership && !guardCf;
        if (checkTlsOwnership)
            RuntimeDetectionState.Enable(ctx, RuntimeDetectionKind.TlsOwnershipLost);
        if (kernelWall || responseProbe)
            RuntimeDetectionState.Enable(ctx, RuntimeDetectionKind.SentinelModified);
        if (dacl || dynamicCode)
            RuntimeDetectionState.Enable(ctx, RuntimeDetectionKind.MitigationRejected);

        uint[] iatSlots = iatHash
            ? ImportTable.Parse(ctx.Pe).Select(imported => imported.ThunkRva).Distinct().Order().ToArray()
            : [];
        ulong[] sentinels = kernelWall || responseProbe
            ? Enumerable.Range(0, 4).Select(_ => (ulong)ctx.Rng.NextInt64() | 1UL).ToArray()
            : [];
        ulong sentinelBasis = FnvOffsetBasis ^ (ulong)ctx.Settings.Seed;
        ulong sentinelHash = HashQwords(sentinels, sentinelBasis);
        ulong taintConstant = (ulong)ctx.Rng.NextInt64() | 1UL;

        // Shared atomic one-shot latch bits in .rmpd:
        // bit 0 = ProcessDynamicCodePolicy applied, bit 1 = process DACL applied,
        // bit 2 = silent-taint XOR applied to SessionKey.
        _latchRva = ctx.AllocData(8, 8);
        // Reserve the fixed-size 15-byte leaf TLS filter trampoline up front so
        // EmitTlsOwnershipCheck knows the exact callback #0 RVA.
        _tlsCallbackRva = guardCf ? 0 : ctx.Alloc(15, 16);

        _monitorRva = EmitMonitor(
            ctx,
            state!,
            _latchRva,
            _tlsCallbackRva,
            iat,
            codeRanges,
            codeBasis,
            iatSlots,
            sentinels,
            sentinelBasis,
            sentinelHash,
            dacl,
            dynamicCode,
            iatHash,
            kernelWall || responseProbe,
            measurement,
            checkTlsOwnership,
            silentTaint,
            toolResponse,
            customMessage,
            taintConstant);
        if (_tlsCallbackRva != 0)
            WriteTlsTrampoline(ctx, _tlsCallbackRva, _monitorRva);

        _state = state;
        _iat = iat;
        _silentTaint = silentTaint;
        _toolResponse = toolResponse;
        _customMessage = customMessage;
        _taintConstant = taintConstant;
        _hasMonitor = true;
        ctx.RegisterInit(_monitorRva, "runtime hardening and integrity monitor");
        if (dacl)
            ctx.Log.Add(new(DaclHardening, "emitted restrictive process DACL policy denying memory, thread, handle, and DACL tampering outside SYSTEM"));
        if (dynamicCode)
            ctx.Log.Add(new(DynamicCodePolicy, "emitted ProcessDynamicCodePolicy startup enforcement"));
        if (iatHash)
            ctx.Log.Add(new(IatHashCheck, $"emitted loader-resolved IAT baseline and thread-start verification for {iatSlots.Length} slots"));
        if (kernelWall)
            ctx.Log.Add(new(KernelWall, $"emitted {sentinels.Length} per-build sentinel probes with runtime verification"));
        if (measurement)
            ctx.Log.Add(new(MeasurementChannels, $"emitted salted code measurement over {codeRanges.Count} relocation-stable ranges"));
        if (checkTlsOwnership)
            ctx.Log.Add(new(TlsVehOwnership, "emitted TLS callback ownership verifier"));
        else if (tlsOwnership)
            ctx.Log.Add(new(TlsVehOwnership, "deferred TLS callback ownership check because Guard CF is enabled"));
        if (silentTaint)
            ctx.Log.Add(new(SilentTaint, "bound shared detection flags to an idempotent session-key taint response"));
        if (toolResponse)
            ctx.Log.Add(new(ToolResponse, "bound shared detection flags to a clean ExitProcess response"));
        ctx.Log.Add(new("runtime-hardening",
            $"emitted monitor at RVA {_monitorRva:X8}: {codeRanges.Count} immutable code ranges, {iatSlots.Length} IAT slots, {sentinels.Length} sentinels"));
    }

    /// <summary>Consumes detections raised by string integrity checks before
    /// the original entry point. The earlier monitor still supplies pre-decryption
    /// taint; this second consumer does not repeat process-policy side effects.</summary>
    public void RegisterAfterStringInitializers(BuildContext ctx)
    {
        if (!ReferenceEquals(ctx, _context) || _postPhaseComplete)
            throw new InvalidOperationException("Register string responses after the pre-entry phase and before entry-point installation.");
        if (_postStringResponseRegistered)
            throw new InvalidOperationException("Post-string response consumer was already registered.");
        _postStringResponseRegistered = true;
        if (!_hasMonitor || (!_silentTaint && !_customMessage && !_toolResponse))
            return;

        // Emit lazily only when StringProtectionPass actually registered at
        // least one string decryptor so images with zero encrypted strings do
        // not carry a dead post-string response stub.
        uint postStringRva = EmitPostStringResponse(ctx, _state!, _latchRva, _silentTaint,
            _taintConstant, _customMessage, _toolResponse, _iat!);
        ctx.RegisterInit(postStringRva, "post-string detection response");
    }

    private static uint EmitPostStringResponse(BuildContext ctx,
        RuntimeDetectionStateLayout state, uint latchRva, bool silentTaint, ulong taintConstant,
        bool customMessage, bool toolResponse, IReadOnlyDictionary<string, uint> iat)
    {
        AntiDebugPass.BuiltRoutine Build(uint selfRva)
        {
            var a = new Asm();
            // Three saves align calls; reserve a separate Windows x64 home area.
            var pushes = new List<(Reg, byte)>();
            foreach (Reg reg in new[] { Reg.Rbx, Reg.R13, Reg.R15 })
            {
                a.PushR(reg);
                pushes.Add((reg, (byte)a.Position));
            }
            a.SubRi(Reg.Rsp, 0x20);
            byte prologEnd = (byte)a.Position;
            a.LoadRuntimeBase(Reg.R15, selfRva);
            a.MovRi(Reg.R13, state.Rva).AddRr(Reg.R13, Reg.R15);
            EmitSharedResponseConsumer(a, latchRva, silentTaint, taintConstant, customMessage, toolResponse, iat);
            a.AddRi(Reg.Rsp, 0x20).PopR(Reg.R15).PopR(Reg.R13).PopR(Reg.Rbx).Ret();
            int codeEnd = a.Position;
            if (customMessage)
            {
                string message = ctx.Settings.CustomMessage ?? "Application integrity check failed.";
                a.Label("response_message").Db(Encoding.UTF8.GetBytes(message + "\0"));
            }
            return new AntiDebugPass.BuiltRoutine(a, codeEnd, AntiDebugPass.BuildUnwindInfo(pushes, 0x20, prologEnd));
        }

        AntiDebugPass.BuiltRoutine probe = Build(0);
        int size = probe.Assembler.Assemble().Length;
        uint rva = ctx.Alloc(size, 16);
        AntiDebugPass.BuiltRoutine built = Build(rva);
        byte[] code = built.Assembler.Assemble();
        if (code.Length != size)
            throw new InvalidOperationException("Post-string response size shifted between layout passes.");
        ctx.WriteStub(rva, code);
        ExceptionTableBuilder.Register(ctx, rva, checked(rva + (uint)built.CodeEnd), built.UnwindInfo!);
        return rva;
    }

    /// <summary>Installs the emitted monitor as the first TLS callback. Call
    /// immediately after EntryPointPass and before relocation rebuilding.</summary>
    public void RunAfterEntryPoint(BuildContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        if (!ReferenceEquals(ctx, _context))
            throw new InvalidOperationException("RunBeforeEntryPoint must be called with this build context first.");
        if (_postPhaseComplete)
            throw new InvalidOperationException("Runtime hardening post-entry phase already ran.");
        _postPhaseComplete = true;
        if (!_hasMonitor)
            return;

        if (ctx.Pe.DllChars.HasFlag(DllCharacteristics.GuardCf) || _tlsCallbackRva == 0)
        {
            ctx.Log.Add(new("runtime-hardening",
                "skipped TLS callback installation to preserve Guard CF integrity; monitor executes through the entry-point init chain"));
            return;
        }

        GuardCfBuilder.RegisterTarget(ctx, _tlsCallbackRva);
        TlsBuilder.Install(ctx, _tlsCallbackRva);
        DataDirectory tls = ctx.Pe.Directory(DataDir.Tls);
        ulong callbacksVa = BinaryPrimitives.ReadUInt64LittleEndian(
            ctx.Pe.ReadRva(tls.RelativeVirtualAddress + 24, 8));
        uint callbacksRva = ctx.Pe.VaToRva(callbacksVa);
        RuntimeDetectionStateLayout state = RuntimeDetectionState.Ensure(ctx);
        ctx.WriteData(
            state.Rva + RuntimeDetectionStateLayout.TlsCallbacksRvaOffset,
            BitConverter.GetBytes((ulong)callbacksRva));
        ctx.Log.Add(new("runtime-hardening",
            $"installed monitor TLS trampoline RVA {_tlsCallbackRva:X8} (target RVA {_monitorRva:X8}) as the outermost TLS callback"));
    }

    /// <summary>Writes a 15-byte leaf TLS callback trampoline that forwards
    /// DLL_PROCESS_ATTACH (1) and DLL_THREAD_ATTACH (2) to the monitor while
    /// ignoring detach notifications (0 and 3).</summary>
    private static void WriteTlsTrampoline(BuildContext ctx, uint trampolineRva, uint monitorRva)
    {
        var a = new Asm();
        // TLS callback ABI: (DllHandle=RCX, Reason=EDX, Reserved=R8).
        a.Mov32Rr(Reg.Rax, Reg.Rdx); // 2B: 89 D0
        a.Db(0xFF, 0xC8);            // 2B: dec eax (1->0, 2->1; 0->0xFFFFFFFF, 3->2)
        a.Db(0x83, 0xF8, 0x01);      // 3B: cmp eax, 1
        a.JccShortOver(Cc.Be, 1);    // 2B: jbe +1 (skip ret when Reason is 1 or 2)
        a.Ret();                     // 1B: C3
        a.JmpRva(trampolineRva, monitorRva); // 5B: tail-jump to monitor
        byte[] bytes = a.Assemble();
        if (bytes.Length != 15)
            throw new InvalidOperationException($"Unexpected TLS trampoline size {bytes.Length}.");
        ctx.WriteStub(trampolineRva, bytes);
    }

    private static uint EmitMonitor(
        BuildContext ctx,
        RuntimeDetectionStateLayout state,
        uint latchRva,
        uint tlsCallbackRva,
        IReadOnlyDictionary<string, uint> iat,
        IReadOnlyList<CodeRange> codeRanges,
        ulong codeBasis,
        IReadOnlyList<uint> iatSlots,
        IReadOnlyList<ulong> sentinels,
        ulong sentinelBasis,
        ulong sentinelHash,
        bool dacl,
        bool dynamicCode,
        bool iatHash,
        bool sentinelMonitor,
        bool measurement,
        bool tlsOwnership,
        bool silentTaint,
        bool toolResponse,
        bool customMessage,
        ulong taintConstant)
    {
        AntiDebugPass.BuiltRoutine Build(uint selfRva)
        {
            var a = new Asm();
            // Five nonvolatile saves align RSP; 0x60 bytes cover shadow space,
            // SetSecurityInfo's stack arguments, and four DACL scratch slots.
            var pushes = new List<(Reg, byte)>();
            foreach (Reg reg in new[] { Reg.Rbx, Reg.R12, Reg.R13, Reg.R14, Reg.R15 })
            {
                a.PushR(reg);
                pushes.Add((reg, (byte)a.Position));
            }
            a.SubRi(Reg.Rsp, 0x60);
            byte prologEnd = (byte)a.Position;
            a.LoadRuntimeBase(Reg.R15, selfRva);
            a.MovRi(Reg.R13, state.Rva).AddRr(Reg.R13, Reg.R15);

            if (measurement && codeRanges.Count > 0)
                EmitCodeMeasurement(a, codeBasis);
            if (iatHash && iatSlots.Count > 0)
                EmitIatMeasurement(a);
            if (sentinelMonitor)
                EmitSentinelMeasurement(a, sentinelBasis, sentinelHash);
            if (tlsOwnership && tlsCallbackRva != 0)
                EmitTlsOwnershipCheck(a, tlsCallbackRva);
            if (dynamicCode)
                EmitDynamicCodePolicy(a, latchRva, iat["SetProcessMitigationPolicy"]);
            if (dacl)
                EmitDaclHardening(a, latchRva, iat);

            EmitSharedResponseConsumer(a, latchRva, silentTaint, taintConstant, customMessage, toolResponse, iat);

            a.AddRi(Reg.Rsp, 0x60);
            a.PopR(Reg.R15).PopR(Reg.R14).PopR(Reg.R13).PopR(Reg.R12).PopR(Reg.Rbx).Ret();
            int codeEnd = a.Position;

            a.Align(8).Label("code_ranges");
            foreach (CodeRange range in codeRanges)
                a.Dq(range.Rva, range.Length);
            a.Dq(0, 0);

            a.Align(8).Label("iat_slots");
            foreach (uint slot in iatSlots)
                a.Dq(slot);
            a.Dq(0);

            a.Align(8).Label("sentinels");
            a.Dq(sentinels.ToArray());
            a.Align(8).Label("sentinel_end");

            if (dacl)
            {
                a.Align(2).Label("process_sddl");
                a.Db(Encoding.Unicode.GetBytes(ProcessDaclSddl + "\0"));
            }
            if (customMessage)
            {
                string message = ctx.Settings.CustomMessage ?? "Application integrity check failed.";
                a.Label("response_message").Db(Encoding.UTF8.GetBytes(message + "\0"));
            }
            return new AntiDebugPass.BuiltRoutine(a, codeEnd, AntiDebugPass.BuildUnwindInfo(pushes, 0x60, prologEnd));
        }

        AntiDebugPass.BuiltRoutine probe = Build(0);
        int size = probe.Assembler.Assemble().Length;
        uint rva = ctx.Alloc(size, 16);
        AntiDebugPass.BuiltRoutine built = Build(rva);
        byte[] code = built.Assembler.Assemble();
        if (code.Length != size)
            throw new InvalidOperationException("Runtime-hardening monitor size shifted between layout passes.");
        ctx.WriteStub(rva, code);
        ExceptionTableBuilder.Register(ctx, rva, checked(rva + (uint)built.CodeEnd), built.UnwindInfo!);
        return rva;
    }

    private static void EmitCodeMeasurement(Asm a, ulong basis)
    {
        a.MovRm(Reg.Rbx, Reg.R13, RuntimeDetectionStateLayout.CodeMeasurementOffset);
        a.MovRi(Reg.R12, unchecked((long)basis));
        a.LeaRip(Reg.R14, "code_ranges");
        a.Label("code_range_next");
        a.MovRm(Reg.Rax, Reg.R14, 0).TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "code_hash_done");
        a.AddRr(Reg.Rax, Reg.R15);
        a.MovRm(Reg.Rdx, Reg.R14, 8);
        a.Label("code_byte_next");
        a.TestRr(Reg.Rdx, Reg.Rdx).Jcc(Cc.E, "code_range_advance");
        a.XorRr(Reg.Rcx, Reg.Rcx).MovRm8(Reg.Rcx, Reg.Rax);
        a.XorRr(Reg.R12, Reg.Rcx);
        a.MovRi(Reg.Rcx, unchecked((long)FnvPrime)).ImulRr(Reg.R12, Reg.Rcx);
        a.IncR(Reg.Rax).DecR(Reg.Rdx).Jmp("code_byte_next");
        a.Label("code_range_advance").AddRi(Reg.R14, 16).Jmp("code_range_next");
        a.Label("code_hash_done").CmpRr(Reg.R12, Reg.Rbx).Jcc(Cc.E, "code_hash_ok");
        RuntimeDetectionState.EmitRecord(a, Reg.R13, RuntimeDetectionKind.CodeModified,
            taintSession: false, taintConstant: 0, labelPrefix: "runtime_code_hash");
        a.Label("code_hash_ok");
    }

    private static void EmitIatMeasurement(Asm a)
    {
        a.MovRi(Reg.Rbx, unchecked((long)FnvOffsetBasis));
        a.LeaRip(Reg.R12, "iat_slots");
        a.Label("iat_hash_next");
        a.MovRm(Reg.Rax, Reg.R12).TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "iat_hash_done");
        a.AddRr(Reg.Rax, Reg.R15).MovRm(Reg.Rax, Reg.Rax);
        a.XorRr(Reg.Rbx, Reg.Rax);
        a.MovRi(Reg.Rcx, unchecked((long)FnvPrime)).ImulRr(Reg.Rbx, Reg.Rcx);
        a.AddRi(Reg.R12, 8).Jmp("iat_hash_next");
        a.Label("iat_hash_done");
        a.MovRm(Reg.Rax, Reg.R13, RuntimeDetectionStateLayout.IatBaselineOffset);
        a.TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.Ne, "iat_compare");
        a.MovMr(Reg.R13, Reg.Rbx, RuntimeDetectionStateLayout.IatBaselineOffset).Jmp("iat_hash_ok");
        a.Label("iat_compare").CmpRr(Reg.Rax, Reg.Rbx).Jcc(Cc.E, "iat_hash_ok");
        RuntimeDetectionState.EmitRecord(a, Reg.R13, RuntimeDetectionKind.IatModified,
            taintSession: false, taintConstant: 0, labelPrefix: "runtime_iat_hash");
        a.Label("iat_hash_ok");
    }

    private static void EmitSentinelMeasurement(Asm a, ulong basis, ulong expected)
    {
        a.MovRi(Reg.Rbx, unchecked((long)basis));
        a.LeaRip(Reg.R12, "sentinels");
        a.LeaRip(Reg.R14, "sentinel_end");
        a.Label("sentinel_next").CmpRr(Reg.R12, Reg.R14).Jcc(Cc.E, "sentinel_done");
        a.MovRm(Reg.Rax, Reg.R12).XorRr(Reg.Rbx, Reg.Rax);
        a.MovRi(Reg.Rcx, unchecked((long)FnvPrime)).ImulRr(Reg.Rbx, Reg.Rcx);
        a.AddRi(Reg.R12, 8).Jmp("sentinel_next");
        a.Label("sentinel_done").MovRi(Reg.Rax, unchecked((long)expected));
        a.CmpRr(Reg.Rbx, Reg.Rax).Jcc(Cc.E, "sentinel_ok");
        RuntimeDetectionState.EmitRecord(a, Reg.R13, RuntimeDetectionKind.SentinelModified,
            taintSession: false, taintConstant: 0, labelPrefix: "runtime_sentinel");
        a.Label("sentinel_ok");
    }

    private static void EmitTlsOwnershipCheck(Asm a, uint expectedCallbackRva)
    {
        // The post-entry phase records the final callback-array RVA. Reading
        // this private value keeps the check alive even when a selected header
        // scrubber intentionally removes e_lfanew and the PE directory table.
        a.MovRm(Reg.Rax, Reg.R13, RuntimeDetectionStateLayout.TlsCallbacksRvaOffset);
        a.TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "tls_lost");
        a.AddRr(Reg.Rax, Reg.R15);
        a.MovRm(Reg.Rcx, Reg.Rax);
        a.MovRi(Reg.Rdx, expectedCallbackRva).AddRr(Reg.Rdx, Reg.R15);
        a.CmpRr(Reg.Rcx, Reg.Rdx).Jcc(Cc.E, "tls_owned");
        a.Label("tls_lost");
        RuntimeDetectionState.EmitRecord(a, Reg.R13, RuntimeDetectionKind.TlsOwnershipLost,
            taintSession: false, taintConstant: 0, labelPrefix: "runtime_tls_owner");
        a.Label("tls_owned");
    }

    private static void EmitDynamicCodePolicy(Asm a, uint latchRva, uint apiIatRva)
    {
        // Apply process-wide dynamic-code mitigation once across TLS + entry invocations.
        a.MovRi(Reg.Rcx, latchRva).AddRr(Reg.Rcx, Reg.R15);
        a.LockBtsMi(Reg.Rcx, 0, 0).Jcc(Cc.B, "dynamic_policy_done");

        a.Mov32Ri(Reg.Rax, 1).MovMr32(Reg.Rsp, Reg.Rax, 0x50); // ProhibitDynamicCode
        a.Mov32Ri(Reg.Rcx, 2);                                 // ProcessDynamicCodePolicy
        a.LeaRd(Reg.Rdx, Reg.Rsp, 0x50);
        a.Mov32Ri(Reg.R8, 4);
        EmitImportedCall(a, apiIatRva);
        a.Test32Rr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "dynamic_policy_failed");
        a.LockBtsMi(Reg.R13, RuntimeDetectionStateLayout.PolicyStatusOffset, 0);
        a.Jmp("dynamic_policy_done");
        a.Label("dynamic_policy_failed");
        RuntimeDetectionState.EmitRecord(a, Reg.R13, RuntimeDetectionKind.MitigationRejected,
            taintSession: false, taintConstant: 0, labelPrefix: "dynamic_policy");
        a.Label("dynamic_policy_done");
    }

    private static void EmitDaclHardening(Asm a, uint latchRva, IReadOnlyDictionary<string, uint> iat)
    {
        // Apply process DACL once across TLS attach + entry-point invocations.
        a.MovRi(Reg.Rcx, latchRva).AddRr(Reg.Rcx, Reg.R15);
        a.LockBtsMi(Reg.Rcx, 0, 1).Jcc(Cc.B, "dacl_done");

        // Scratch layout: +40 SD*, +48 ACL*, +50 BOOL present, +58 BOOL defaulted.
        a.XorRr(Reg.Rax, Reg.Rax);
        a.MovMr(Reg.Rsp, Reg.Rax, 0x40).MovMr(Reg.Rsp, Reg.Rax, 0x48);
        a.MovMr(Reg.Rsp, Reg.Rax, 0x50).MovMr(Reg.Rsp, Reg.Rax, 0x58);

        a.LeaRip(Reg.Rcx, "process_sddl").Mov32Ri(Reg.Rdx, 1);
        a.LeaRd(Reg.R8, Reg.Rsp, 0x40).XorRr(Reg.R9, Reg.R9);
        EmitImportedCall(a, iat["ConvertStringSecurityDescriptorToSecurityDescriptorW"]);
        a.Test32Rr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "dacl_failed_no_free");

        a.MovRm(Reg.Rcx, Reg.Rsp, 0x40).LeaRd(Reg.Rdx, Reg.Rsp, 0x50);
        a.LeaRd(Reg.R8, Reg.Rsp, 0x48).LeaRd(Reg.R9, Reg.Rsp, 0x58);
        EmitImportedCall(a, iat["GetSecurityDescriptorDacl"]);
        a.Test32Rr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "dacl_failed_free");
        a.MovRm32(Reg.Rax, Reg.Rsp, 0x50).Test32Rr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "dacl_failed_free");
        a.MovRm(Reg.Rax, Reg.Rsp, 0x48).TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "dacl_failed_free");

        a.XorRr(Reg.Rax, Reg.Rax).MovMr(Reg.Rsp, Reg.Rax, 0x20);
        a.MovRm(Reg.Rax, Reg.Rsp, 0x48).MovMr(Reg.Rsp, Reg.Rax, 0x28);
        a.XorRr(Reg.Rax, Reg.Rax).MovMr(Reg.Rsp, Reg.Rax, 0x30); // pSacl (argument 7)
        // DACL_SECURITY_INFORMATION (0x4) | PROTECTED_DACL_SECURITY_INFORMATION (0x80000000)
        // prevents inherited ACEs from re-opening denied process access rights.
        a.MovRi(Reg.Rcx, -1).Mov32Ri(Reg.Rdx, 6).Mov32Ri(Reg.R8, 0x80000004u).XorRr(Reg.R9, Reg.R9);
        EmitImportedCall(a, iat["SetSecurityInfo"]);
        a.Mov32Rr(Reg.R14, Reg.Rax);
        a.MovRm(Reg.Rcx, Reg.Rsp, 0x40);
        EmitImportedCall(a, iat["LocalFree"]);
        a.Test32Rr(Reg.R14, Reg.R14).Jcc(Cc.Ne, "dacl_failed_no_free");
        a.LockBtsMi(Reg.R13, RuntimeDetectionStateLayout.PolicyStatusOffset, 1);
        a.Jmp("dacl_done");

        a.Label("dacl_failed_free");
        a.MovRm(Reg.Rcx, Reg.Rsp, 0x40);
        EmitImportedCall(a, iat["LocalFree"]);
        a.Label("dacl_failed_no_free");
        RuntimeDetectionState.EmitRecord(a, Reg.R13, RuntimeDetectionKind.MitigationRejected,
            taintSession: false, taintConstant: 0, labelPrefix: "dacl_policy");
        a.Label("dacl_done");
    }

    private static void EmitResponse(
        Asm a,
        bool customMessage,
        bool toolResponse,
        IReadOnlyDictionary<string, uint> iat)
    {
        if (customMessage)
        {
            a.LeaRip(Reg.Rcx, "response_message");
            EmitImportedCall(a, iat["OutputDebugStringA"]);
        }
        if (toolResponse)
        {
            a.XorRr(Reg.Rcx, Reg.Rcx);
            EmitImportedCall(a, iat["ExitProcess"]);
        }
    }

    private static void EmitSharedResponseConsumer(
        Asm a,
        uint latchRva,
        bool silentTaint,
        ulong taintConstant,
        bool customMessage,
        bool toolResponse,
        IReadOnlyDictionary<string, uint> iat)
    {
        if (!silentTaint && !customMessage && !toolResponse)
            return;

        a.MovRm(Reg.Rbx, Reg.R13, RuntimeDetectionStateLayout.DetectionFlagsOffset);
        a.MovRm(Reg.Rax, Reg.R13, RuntimeDetectionStateLayout.RespondedFlagsOffset);
        a.CmpRr(Reg.Rbx, Reg.Rax).Jcc(Cc.E, "shared_response_done");
        if (silentTaint)
        {
            // Gate the session-key XOR with an atomic one-shot bit so concurrent
            // threads can never apply the same XOR twice and cancel the taint.
            a.MovRi(Reg.Rcx, latchRva).AddRr(Reg.Rcx, Reg.R15);
            a.LockBtsMi(Reg.Rcx, 0, 2).Jcc(Cc.B, "shared_taint_done");
            a.MovRr(Reg.Rax, Reg.Rbx);
            a.MovRi(Reg.Rcx, unchecked((long)taintConstant)).XorRr(Reg.Rax, Reg.Rcx);
            a.LockXorMr(Reg.R13, Reg.Rax, RuntimeDetectionStateLayout.SessionKeyOffset);
            a.Label("shared_taint_done");
        }
        a.MovMr(Reg.R13, Reg.Rbx, RuntimeDetectionStateLayout.RespondedFlagsOffset);
        EmitResponse(a, customMessage, toolResponse, iat);
        a.Label("shared_response_done");
    }

    private static void EmitImportedCall(Asm a, uint iatRva)
    {
        a.MovRi(Reg.Rax, iatRva).AddRr(Reg.Rax, Reg.R15).CallMem(Reg.Rax);
    }

    private static List<CodeRange> BuildStableCodeRanges(BuildContext ctx)
    {
        uint[] relocations = Relocations.Enumerate(ctx.Pe)
            .Where(entry => entry.Type == Relocations.TypeAbsolute)
            .Select(entry => entry.Rva)
            // New absolute slots have not reached the rebuilt relocation table
            // yet. Measuring their preferred VAs would report tampering on ASLR.
            .Concat(ctx.RelocSlots)
            .Distinct()
            .Order()
            .ToArray();
        var requested = new List<CodeRange>();
        foreach (FunctionDescriptor function in ctx.Functions.OrderBy(item => item.BeginRva))
        {
            AddRange(function.BeginRva, function.Size);
            // The original entry still matters, but it is now a trampoline.
            // Cover the executing body as well, including immutable VM bytecode.
            if (ctx.FunctionTransformations.TryGetValue(function.BeginRva, out var transformed))
                AddRange(transformed.ProtectedRva, transformed.ProtectedSize);
        }

        // Merge overlap before subtracting fixups so each byte is measured once.
        // The scan remains linear after sorting; generated coverage is limited
        // to claimed bodies, never the entire reserved runtime code section.
        var merged = new List<CodeRange>();
        foreach (CodeRange range in requested.OrderBy(range => range.Rva))
        {
            if (merged.Count == 0 || (ulong)merged[^1].Rva + merged[^1].Length < range.Rva)
                merged.Add(range);
            else
            {
                CodeRange previous = merged[^1];
                ulong end = Math.Max((ulong)previous.Rva + previous.Length, (ulong)range.Rva + range.Length);
                merged[^1] = previous with { Length = checked((uint)(end - previous.Rva)) };
            }
        }
        var ranges = new List<CodeRange>();
        int fixupIndex = 0;
        foreach (CodeRange range in merged)
        {
            ulong cursor = range.Rva, end = cursor + range.Length;
            while (fixupIndex < relocations.Length && (ulong)relocations[fixupIndex] + 8 <= cursor)
                fixupIndex++;
            int index = fixupIndex;
            while (index < relocations.Length && relocations[index] < end)
            {
                ulong relocation = relocations[index++];
                if (relocation > cursor)
                    ranges.Add(new CodeRange((uint)cursor, (uint)(relocation - cursor)));
                cursor = Math.Max(cursor, Math.Min(end, relocation + 8));
            }
            if (cursor < end) ranges.Add(new CodeRange((uint)cursor, (uint)(end - cursor)));
        }
        return ranges;

        void AddRange(uint start, uint length)
        {
            PeImage.Section? section = ctx.Pe.SectionFromRva(start);
            if (section is null || !section.IsExecutable || !ctx.Pe.TryRvaToOffset(start, out _)) return;
            ulong end = Math.Min((ulong)start + length, (ulong)section.VirtualAddress + section.SizeOfRawData);
            if (end > start) requested.Add(new CodeRange(start, checked((uint)(end - start))));
        }
    }

    private static ulong HashCodeRanges(PeImage pe, IEnumerable<CodeRange> ranges, ulong basis)
    {
        ulong hash = basis;
        foreach (CodeRange range in ranges)
        {
            foreach (byte value in pe.ReadRva(range.Rva, checked((int)range.Length)))
            {
                hash ^= value;
                hash *= FnvPrime;
            }
        }
        return hash;
    }

    private static ulong HashQwords(IEnumerable<ulong> values, ulong basis)
    {
        ulong hash = basis;
        foreach (ulong value in values)
        {
            hash ^= value;
            hash *= FnvPrime;
        }
        return hash;
    }

    private static void EmitMetadata(BuildContext ctx, string magic, string value, string logPass, string description)
    {
        byte[] payload = Encoding.UTF8.GetBytes(value);
        if (payload.Length > MaximumMetadataBytes)
            throw new ArgumentException($"{description} exceeds {MaximumMetadataBytes} UTF-8 bytes.");

        int padding = ctx.Rng.Next(0, 64);
        if (padding > 0)
        {
            var noise = new byte[padding];
            ctx.Rng.NextBytes(noise);
            uint paddingRva = ctx.Alloc(padding);
            ctx.WriteStub(paddingRva, noise);
        }

        var record = new byte[32 + payload.Length];
        Encoding.ASCII.GetBytes(magic).CopyTo(record, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(12), (uint)payload.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(16), (ulong)ctx.Settings.Seed);
        BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(24), HashBytes(payload));
        payload.CopyTo(record, 32);
        uint rva = ctx.Alloc(record.Length, 8);
        ctx.WriteStub(rva, record);
        ctx.Log.Add(new(logPass, $"embedded {payload.Length}-byte {description} record at build-specific RVA {rva:X8}"));
    }

    private static ulong HashBytes(IEnumerable<byte> values)
    {
        ulong hash = FnvOffsetBasis;
        foreach (byte value in values)
        {
            hash ^= value;
            hash *= FnvPrime;
        }
        return hash;
    }

    private static void SetPolicyStatus(BuildContext ctx, RuntimeDetectionStateLayout state, ulong flag)
    {
        ulong current = BinaryPrimitives.ReadUInt64LittleEndian(
            ctx.Pe.ReadRva(state.Rva + RuntimeDetectionStateLayout.PolicyStatusOffset, 8));
        ctx.WriteData(state.Rva + RuntimeDetectionStateLayout.PolicyStatusOffset, BitConverter.GetBytes(current | flag));
    }

    private static void Merge(Dictionary<string, uint> destination, IReadOnlyDictionary<string, uint> source)
    {
        foreach ((string name, uint rva) in source)
            destination[name] = rva;
    }

    private static bool Enabled(BuildContext ctx, string knob) => ctx.Level(knob) != ProtectionLevel.Off;

    private readonly record struct CodeRange(uint Rva, uint Length);
}
