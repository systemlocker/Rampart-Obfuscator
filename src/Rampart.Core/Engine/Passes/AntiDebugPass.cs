using System.Buffers.Binary;
using System.Text;
using Rampart.Pe;
using Rampart.X64;

namespace Rampart.Engine.Passes;

/// <summary>
/// Emits the first, deliberately non-destructive anti-debug runtime. Detection
/// results are retained in private .rmpd state records for later response
/// passes; a clean process, and even a detected process, continues normally.
/// Windows APIs are added to a private import descriptor instead of using
/// version-specific syscall numbers, which keeps the stubs portable across
/// supported x64 Windows releases.
/// </summary>
public sealed class AntiDebugPass
{
    private const string ChannelSweep = "anti-debug.channel-sweep";
    private const string InlineHookCheck = "anti-debug.inline-hook-check";
    private const string VehTamper = "anti-debug.veh-tamper";
    private const string DllNotify = "anti-debug.dll-notify";

    public void Run(BuildContext ctx)
    {
        bool channelSweep = ctx.Level(ChannelSweep) != Config.ProtectionLevel.Off;
        bool inlineHookCheck = ctx.Level(InlineHookCheck) != Config.ProtectionLevel.Off;
        bool vehTamper = ctx.Level(VehTamper) != Config.ProtectionLevel.Off;
        bool dllNotify = ctx.Level(DllNotify) != Config.ProtectionLevel.Off;
        if (!channelSweep && !inlineHookCheck && !vehTamper && !dllNotify)
            return;

        if (channelSweep || inlineHookCheck || vehTamper)
            RuntimeDetectionState.Enable(ctx, RuntimeDetectionKind.DebuggerObserved);
        if (dllNotify)
            RuntimeDetectionState.Enable(ctx, RuntimeDetectionKind.ForeignModuleObserved);

        var requests = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        if (channelSweep)
        {
            Request(requests, "KERNEL32.DLL", "IsDebuggerPresent");
            Request(requests, "KERNEL32.DLL", "CheckRemoteDebuggerPresent");
        }
        if (inlineHookCheck)
        {
            Request(requests, "NTDLL.DLL", "NtQueryInformationProcess");
            Request(requests, "NTDLL.DLL", "NtProtectVirtualMemory");
            Request(requests, "NTDLL.DLL", "LdrLoadDll");
        }
        if (vehTamper)
        {
            Request(requests, "NTDLL.DLL", "RtlAddVectoredExceptionHandler");
            Request(requests, "KERNEL32.DLL", "RaiseException");
        }
        if (dllNotify)
            Request(requests, "NTDLL.DLL", "LdrRegisterDllNotification");

        IReadOnlyDictionary<string, uint> iat = RuntimeImports.Append(ctx, requests);
        if (channelSweep)
            EmitChannelSweep(ctx, iat);
        if (inlineHookCheck)
            EmitInlineHookCheck(ctx, iat);
        if (vehTamper)
            EmitVehRegistration(ctx, iat);
        if (dllNotify)
            EmitDllNotification(ctx, iat);
    }

    private static void EmitChannelSweep(BuildContext ctx, IReadOnlyDictionary<string, uint> iat)
    {
        RuntimeDetectionStateLayout detectionState = RuntimeDetectionState.Ensure(ctx);
        uint channelStateRva = ctx.AllocData(32, 8);

        Asm Build(uint selfRva)
        {
            var a = new Asm();
            // Entry RSP is 8 mod 16. Four saves plus 0x28 bytes leave it
            // 16-aligned at both API call sites and reserve the shadow area.
            a.PushR(Reg.Rbx).PushR(Reg.Rsi).PushR(Reg.Rdi).PushR(Reg.R15).SubRi(Reg.Rsp, 0x28);
            a.LoadRuntimeBase(Reg.R15, selfRva).AddRi(Reg.R15, checked((int)detectionState.Rva));

            a.CallRip("ext::IsDebuggerPresent");
            a.MovRipStore(Reg.Rax, "channel_state", 0);

            // PEB.BeingDebugged is a byte at offset 2 on native x64 Windows.
            a.MovRegPeb(Reg.Rbx);
            a.XorRr(Reg.Rax, Reg.Rax).MovRm8(Reg.Rax, Reg.Rbx, 2);
            a.MovRipStore(Reg.Rax, "channel_state", 8);

            // CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote).
            a.XorRr(Reg.Rax, Reg.Rax).MovMr(Reg.Rsp, Reg.Rax, 0x20);
            a.MovRi(Reg.Rcx, -1).LeaRd(Reg.Rdx, Reg.Rsp, 0x20);
            a.CallRip("ext::CheckRemoteDebuggerPresent");
            a.MovRipStore(Reg.Rax, "channel_state", 16);
            a.MovRm32(Reg.Rax, Reg.Rsp, 0x20);
            a.MovRipStore(Reg.Rax, "channel_state", 24);

            a.MovRip(Reg.Rax, "channel_state", 0).TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.Ne, "debug_seen");
            a.MovRip(Reg.Rax, "channel_state", 8).TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.Ne, "debug_seen");
            a.MovRip(Reg.Rax, "channel_state", 24).TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "channel_done");
            a.Label("debug_seen");
            RuntimeDetectionState.EmitRecord(
                a,
                Reg.R15,
                RuntimeDetectionKind.DebuggerObserved,
                taintSession: false,
                taintConstant: 0,
                labelPrefix: "channel_debug");

            a.Label("channel_done");
            a.AddRi(Reg.Rsp, 0x28).PopR(Reg.R15).PopR(Reg.Rdi).PopR(Reg.Rsi).PopR(Reg.Rbx).Ret();
            a.Align(8).Label("channel_state").Dq(0, 0, 0, 0);
            a.Db(Encoding.ASCII.GetBytes("RMPT.ADBG.CHAN\0"));
            AddExternalSlots(a, "IsDebuggerPresent", "CheckRemoteDebuggerPresent");
            return a;
        }

        uint rva = WriteRoutine(ctx, Build, iat,
            new Dictionary<string, uint> { ["channel_state"] = channelStateRva });
        ctx.RegisterInit(rva, "anti-debug channel sweep (three independent channels)");
        ctx.Log.Add(new("anti-debug.channel-sweep",
            $"emitted startup probes at RVA {rva:X8}: IsDebuggerPresent, PEB.BeingDebugged, and CheckRemoteDebuggerPresent"));
    }

    private static void EmitInlineHookCheck(BuildContext ctx, IReadOnlyDictionary<string, uint> iat)
    {
        string[] targets = ["NtQueryInformationProcess", "NtProtectVirtualMemory", "LdrLoadDll"];
        RuntimeDetectionStateLayout detectionState = RuntimeDetectionState.Ensure(ctx);
        ulong hashSeed = (ulong)ctx.Rng.NextInt64() | 1UL;
        uint hookStateRva = ctx.AllocData(32, 8);

        Asm Build(uint selfRva)
        {
            var a = new Asm();
            a.PushR(Reg.Rbx).PushR(Reg.R15);
            a.LoadRuntimeBase(Reg.R15, selfRva).AddRi(Reg.R15, checked((int)detectionState.Rva));

            // Hash 16 prologue bytes for each export. The fingerprints provide
            // evidence for later periodic comparisons, while the startup scan
            // below catches common JMP/INT3 inline-hook forms immediately.
            for (int target = 0; target < targets.Length; target++)
            {
                a.MovRip(Reg.Rbx, $"ext::{targets[target]}");
                a.MovRi(Reg.Rdx, unchecked((long)hashSeed));
                for (int offset = 0; offset < 16; offset++)
                {
                    a.XorRr(Reg.Rax, Reg.Rax).MovRm8(Reg.Rax, Reg.Rbx, offset);
                    a.XorRr(Reg.Rdx, Reg.Rax).RolRi(Reg.Rdx, 5);
                    a.AddRi(Reg.Rdx, unchecked((int)0x9E3779B9));
                }
                a.MovRipStore(Reg.Rdx, "hook_state", target * 8);
            }

            for (int target = 0; target < targets.Length; target++)
            {
                string next = $"hook_next_{target}";
                a.MovRip(Reg.Rbx, $"ext::{targets[target]}");
                EmitByteEqualsJump(a, Reg.Rbx, 0, 0xE9, "hook_found"); // jmp rel32
                EmitByteEqualsJump(a, Reg.Rbx, 0, 0xEB, "hook_found"); // jmp rel8
                EmitByteEqualsJump(a, Reg.Rbx, 0, 0xCC, "hook_found"); // breakpoint patch
                EmitByteEqualsJump(a, Reg.Rbx, 0, 0xFF, $"hook_ff_{target}");
                a.Jmp(next);
                a.Label($"hook_ff_{target}");
                EmitByteEqualsJump(a, Reg.Rbx, 1, 0x25, "hook_found"); // jmp [rip+disp32]
                a.Label(next);
            }
            a.Jmp("hook_done");
            a.Label("hook_found").MovRi(Reg.Rax, 1).MovRipStore(Reg.Rax, "hook_state", 24);
            RuntimeDetectionState.EmitRecord(
                a,
                Reg.R15,
                RuntimeDetectionKind.DebuggerObserved,
                taintSession: false,
                taintConstant: 0,
                labelPrefix: "inline_hook");
            a.Label("hook_done").PopR(Reg.R15).PopR(Reg.Rbx).Ret();

            a.Align(8).Label("hook_state").Dq(0, 0, 0, 0);
            a.Db(Encoding.ASCII.GetBytes("RMPT.ADBG.HOOK\0"));
            AddExternalSlots(a, targets);
            return a;
        }

        uint rva = WriteRoutine(ctx, Build, iat,
            new Dictionary<string, uint> { ["hook_state"] = hookStateRva });
        ctx.RegisterInit(rva, "ntdll prologue hashing and inline-hook scan");
        ctx.Log.Add(new("anti-debug.inline-hook-check",
            $"emitted salted prologue fingerprints and trampoline checks for {targets.Length} ntdll exports at RVA {rva:X8}"));
    }

    private static void EmitVehRegistration(BuildContext ctx, IReadOnlyDictionary<string, uint> iat)
    {
        const uint ProbeExceptionCode = 0xE042_4D50; // private, continuable application exception
        RuntimeDetectionStateLayout detectionState = RuntimeDetectionState.Ensure(ctx);
        uint handlerHitsRva = ctx.AllocData(8, 8);

        Asm Handler(uint selfRva)
        {
            var a = new Asm();
            // Handle only Rampart's private verification exception. All real
            // application exceptions continue down the existing VEH/SEH chain.
            a.MovRm(Reg.Rax, Reg.Rcx, 0).MovRm32(Reg.Rdx, Reg.Rax, 0);
            a.MovRi(Reg.Rax, ProbeExceptionCode).CmpRr(Reg.Rdx, Reg.Rax);
            a.Jcc(Cc.Ne, "veh_continue_search");
            a.MovRi(Reg.Rax, 1).MovRipStore(Reg.Rax, "veh_hits");
            a.MovRi(Reg.Rax, -1).Ret(); // EXCEPTION_CONTINUE_EXECUTION
            a.Label("veh_continue_search").XorRr(Reg.Rax, Reg.Rax).Ret();
            a.Align(8).Label("veh_hits").Dq(0);
            a.Db(Encoding.ASCII.GetBytes("RMPT.ADBG.VEH.HANDLER\0"));
            return a;
        }

        uint handlerRva = WriteRoutine(ctx, Handler, iat,
            new Dictionary<string, uint> { ["veh_hits"] = handlerHitsRva });
        GuardCfBuilder.RegisterTarget(ctx, handlerRva);

        Asm Init(uint selfRva)
        {
            var a = new Asm();
            a.PushR(Reg.R14).PushR(Reg.R15).SubRi(Reg.Rsp, 0x28);
            a.LoadRuntimeBase(Reg.R15, selfRva);
            a.MovRr(Reg.R14, Reg.R15).AddRi(Reg.R14, checked((int)detectionState.Rva));
            a.MovRi(Reg.Rcx, 1); // first handler
            a.MovRi(Reg.Rdx, handlerRva).AddRr(Reg.Rdx, Reg.R15);
            a.CallRip("ext::RtlAddVectoredExceptionHandler");
            a.MovRipStore(Reg.Rax, "veh_state", 0); // nonzero registration handle
            a.TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "veh_done");
            a.MovRi(Reg.Rax, 1).MovRipStore(Reg.Rax, "veh_state", 8);

            // A private continuable exception proves that our callback is not
            // merely registered but is actually reachable in the live chain.
            a.MovRi(Reg.Rcx, ProbeExceptionCode);
            a.XorRr(Reg.Rdx, Reg.Rdx).XorRr(Reg.R8, Reg.R8).XorRr(Reg.R9, Reg.R9);
            a.CallRip("ext::RaiseException");
            a.MovRi(Reg.Rax, handlerHitsRva).AddRr(Reg.Rax, Reg.R15).MovRm(Reg.Rax, Reg.Rax);
            a.MovRipStore(Reg.Rax, "veh_state", 16);
            a.TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.Ne, "veh_done");
            RuntimeDetectionState.EmitRecord(
                a,
                Reg.R14,
                RuntimeDetectionKind.DebuggerObserved,
                taintSession: false,
                taintConstant: 0,
                labelPrefix: "veh_missing");
            a.Label("veh_done");
            a.AddRi(Reg.Rsp, 0x28).PopR(Reg.R15).PopR(Reg.R14).Ret();
            a.Align(8).Label("veh_state").Dq(0, 0, 0);
            a.Db(Encoding.ASCII.GetBytes("RMPT.ADBG.VEH.STATE\0"));
            AddExternalSlots(a, "RtlAddVectoredExceptionHandler", "RaiseException");
            return a;
        }

        uint vehStateRva = ctx.AllocData(24, 8);
        uint initRva = WriteRoutine(ctx, Init, iat,
            new Dictionary<string, uint> { ["veh_state"] = vehStateRva });
        ctx.RegisterInit(initRva, "passive vectored exception handler registration");
        ctx.Log.Add(new("anti-debug.veh-tamper",
            $"emitted passive VEH callback at RVA {handlerRva:X8} and registration check at RVA {initRva:X8}"));
    }

    private static void EmitDllNotification(BuildContext ctx, IReadOnlyDictionary<string, uint> iat)
    {
        uint notifyStateRva = ctx.AllocData(32, 8);
        Asm Callback(uint selfRva)
        {
            var a = new Asm();
            // Ldr callback arguments: reason, notification data, context.
            a.MovRip(Reg.Rax, "notify_state", 0).IncR(Reg.Rax);
            a.MovRipStore(Reg.Rax, "notify_state", 0);
            a.MovRipStore(Reg.Rcx, "notify_state", 8);
            a.MovRipStore(Reg.Rdx, "notify_state", 16);
            a.MovRipStore(Reg.R8, "notify_state", 24);
            a.Ret();
            a.Align(8).Label("notify_state").Dq(0, 0, 0, 0);
            a.Db(Encoding.ASCII.GetBytes("RMPT.ADBG.LDR.CALLBACK\0"));
            return a;
        }

        uint callbackRva = WriteRoutine(ctx, Callback, iat,
            new Dictionary<string, uint> { ["notify_state"] = notifyStateRva });
        GuardCfBuilder.RegisterTarget(ctx, callbackRva);

        Asm Init(uint selfRva)
        {
            var a = new Asm();
            a.PushR(Reg.R15).SubRi(Reg.Rsp, 0x20);
            a.LoadRuntimeBase(Reg.R15, selfRva);
            a.XorRr(Reg.Rcx, Reg.Rcx); // flags = 0
            a.MovRi(Reg.Rdx, callbackRva).AddRr(Reg.Rdx, Reg.R15);
            a.XorRr(Reg.R8, Reg.R8);   // optional context
            a.LeaRip(Reg.R9, "ldr_state", 8); // cookie out
            a.CallRip("ext::LdrRegisterDllNotification");
            a.MovRipStore(Reg.Rax, "ldr_state", 0); // NTSTATUS
            a.AddRi(Reg.Rsp, 0x20).PopR(Reg.R15).Ret();
            a.Align(8).Label("ldr_state").Dq(0, 0);
            a.Db(Encoding.ASCII.GetBytes("RMPT.ADBG.LDR.STATE\0"));
            AddExternalSlots(a, "LdrRegisterDllNotification");
            return a;
        }

        uint loaderStateRva = ctx.AllocData(16, 8);
        uint initRva = WriteRoutine(ctx, Init, iat,
            new Dictionary<string, uint> { ["ldr_state"] = loaderStateRva });
        ctx.RegisterInit(initRva, "native loader notification registration");
        ctx.Log.Add(new("anti-debug.dll-notify",
            $"emitted LdrRegisterDllNotification callback at RVA {callbackRva:X8} and registrar at RVA {initRva:X8}"));
    }

    private static void EmitByteEqualsJump(Asm a, Reg address, int offset, byte value, string target)
    {
        a.XorRr(Reg.Rax, Reg.Rax).MovRm8(Reg.Rax, address, offset);
        a.MovRi(Reg.Rdx, value).CmpRr(Reg.Rax, Reg.Rdx).Jcc(Cc.E, target);
    }

    internal static uint WriteRoutine(
        BuildContext ctx,
        Func<uint, Asm> build,
        IReadOnlyDictionary<string, uint> externalIat,
        IReadOnlyDictionary<string, uint>? externalData = null)
    {
        int size = build(0).Assemble().Length;
        uint rva = ctx.Alloc(size, 16);
        Asm assembler = build(rva);
        byte[] code = assembler.Assemble();
        if (code.Length != size)
            throw new InvalidOperationException("Anti-debug routine size shifted between layout passes.");

        foreach (var (position, target, _) in assembler.RipFixups)
        {
            if (!target.StartsWith("ext::", StringComparison.Ordinal))
                continue;
            string api = target["ext::".Length..];
            uint targetRva = externalIat[api];
            long displacement = (long)targetRva - ((long)rva + position + 4);
            if (displacement is < int.MinValue or > int.MaxValue)
                throw new InvalidOperationException($"Runtime import '{api}' is outside RIP-relative range.");
            BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(position), (int)displacement);
        }

        if (externalData != null)
            BuildContext.PatchRipReferences(code, assembler, rva, externalData);

        ctx.WriteStub(rva, code);
        return rva;
    }

    internal static void AddExternalSlots(Asm a, params string[] names)
    {
        foreach (string name in names.Distinct(StringComparer.Ordinal))
            a.Align(8).Label($"ext::{name}").Dq(0);
    }

    internal static void Request(
        Dictionary<string, HashSet<string>> requests,
        string dll,
        string function)
    {
        if (!requests.TryGetValue(dll, out HashSet<string>? functions))
            requests.Add(dll, functions = new HashSet<string>(StringComparer.Ordinal));
        functions.Add(function);
    }

    /// <summary>Appends import descriptors while leaving every existing thunk,
    /// name, and descriptor value intact. The loader accepts descriptors in any
    /// readable image section; keeping the new IAT in .rmpd also gives callbacks
    /// stable slots for the process lifetime.</summary>
    internal static class RuntimeImports
    {
        private sealed record ModuleLayout(
            string Dll,
            string[] Functions,
            int DllOffset,
            int[] HintNameOffsets,
            int IntOffset,
            int IatOffset);

        public static IReadOnlyDictionary<string, uint> Append(
            BuildContext ctx,
            Dictionary<string, HashSet<string>> requests)
        {
            PeImage pe = ctx.Pe;
            List<byte[]> existing = ReadDescriptors(pe);
            var modules = requests
                .OrderBy(item => item.Key, StringComparer.OrdinalIgnoreCase)
                .Select(item => (item.Key, item.Value.OrderBy(name => name, StringComparer.Ordinal).ToArray()))
                .ToList();

            int cursor = checked((existing.Count + modules.Count + 1) * 20);
            var layouts = new List<ModuleLayout>(modules.Count);
            foreach (var (dll, functions) in modules)
            {
                int dllOffset = cursor;
                cursor = checked(cursor + Encoding.ASCII.GetByteCount(dll) + 1);
                int[] hintNames = new int[functions.Length];
                for (int i = 0; i < functions.Length; i++)
                {
                    cursor = Align(cursor, 2);
                    hintNames[i] = cursor;
                    cursor = checked(cursor + 2 + Encoding.ASCII.GetByteCount(functions[i]) + 1);
                }
                cursor = Align(cursor, 8);
                int intOffset = cursor;
                cursor = checked(cursor + (functions.Length + 1) * 8);
                int iatOffset = cursor;
                cursor = checked(cursor + (functions.Length + 1) * 8);
                layouts.Add(new ModuleLayout(dll, functions, dllOffset, hintNames, intOffset, iatOffset));
            }

            uint baseRva = ctx.AllocData(cursor, 8);
            var blob = new byte[cursor];
            for (int i = 0; i < existing.Count; i++)
                existing[i].CopyTo(blob, i * 20);

            var result = new Dictionary<string, uint>(StringComparer.Ordinal);
            for (int moduleIndex = 0; moduleIndex < layouts.Count; moduleIndex++)
            {
                ModuleLayout module = layouts[moduleIndex];
                int descriptor = (existing.Count + moduleIndex) * 20;
                BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(descriptor), baseRva + (uint)module.IntOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(descriptor + 12), baseRva + (uint)module.DllOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(descriptor + 16), baseRva + (uint)module.IatOffset);
                Encoding.ASCII.GetBytes(module.Dll + "\0").CopyTo(blob, module.DllOffset);

                for (int functionIndex = 0; functionIndex < module.Functions.Length; functionIndex++)
                {
                    string function = module.Functions[functionIndex];
                    int hintName = module.HintNameOffsets[functionIndex];
                    Encoding.ASCII.GetBytes(function + "\0").CopyTo(blob, hintName + 2);
                    ulong hintNameRva = baseRva + (uint)hintName;
                    BinaryPrimitives.WriteUInt64LittleEndian(
                        blob.AsSpan(module.IntOffset + functionIndex * 8), hintNameRva);
                    BinaryPrimitives.WriteUInt64LittleEndian(
                        blob.AsSpan(module.IatOffset + functionIndex * 8), hintNameRva);
                    result.Add(function, baseRva + (uint)(module.IatOffset + functionIndex * 8));
                }
            }

            ctx.WriteData(baseRva, blob);
            pe.SetDirectory(DataDir.Import, baseRva, (uint)((existing.Count + modules.Count + 1) * 20));
            if (pe.Directory(DataDir.Iat).IsEmpty && layouts.Count > 0)
            {
                int first = layouts.Min(module => module.IatOffset);
                int end = layouts.Max(module => module.IatOffset + (module.Functions.Length + 1) * 8);
                pe.SetDirectory(DataDir.Iat, baseRva + (uint)first, (uint)(end - first));
            }
            ctx.Log.Add(new("anti-debug.imports",
                $"appended {result.Count} runtime APIs in {modules.Count} descriptors; preserved {existing.Count} original descriptors"));
            return result;
        }

        private static List<byte[]> ReadDescriptors(PeImage pe)
        {
            var descriptors = new List<byte[]>();
            DataDirectory directory = pe.Directory(DataDir.Import);
            if (directory.IsEmpty)
                return descriptors;

            // Directory sizes in the wild are inconsistent about including the
            // null descriptor, so terminate by contents with a hard safety cap.
            uint rva = directory.RelativeVirtualAddress;
            for (int i = 0; i < 4096; i++, rva += 20)
            {
                byte[] descriptor = pe.ReadRva(rva, 20);
                if (descriptor.All(value => value == 0))
                    return descriptors;
                descriptors.Add(descriptor);
            }
            throw new BadImageFormatException("Import directory has no terminating descriptor within 4096 entries.");
        }

        private static int Align(int value, int alignment) =>
            checked((value + alignment - 1) / alignment * alignment);
    }
}
