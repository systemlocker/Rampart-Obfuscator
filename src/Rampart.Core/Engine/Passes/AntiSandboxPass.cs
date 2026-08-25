using System.Text;
using Rampart.X64;

namespace Rampart.Engine.Passes;

/// <summary>
/// Conservative Light-level sandbox observations. Each check records evidence
/// in its own inspectable state block and raises the shared SandboxObserved bit;
/// it never exits, sleeps, crashes, or changes application results.
/// </summary>
public sealed class AntiSandboxPass
{
    private const string VirtualisationDetect = "anti-sandbox.virtualisation-detect";
    private const string FingerprintSuite = "anti-sandbox.fingerprint-suite";
    private const string HumanGate = "anti-sandbox.human-gate";
    private const int GenerousIdleWindowMilliseconds = 30 * 60 * 1000;

    public void Run(BuildContext ctx)
    {
        bool virtualisation = ctx.Level(VirtualisationDetect) != Config.ProtectionLevel.Off;
        bool fingerprints = ctx.Level(FingerprintSuite) != Config.ProtectionLevel.Off;
        bool humanGate = ctx.Level(HumanGate) != Config.ProtectionLevel.Off;
        if (!virtualisation && !fingerprints && !humanGate)
            return;

        RuntimeDetectionState.Enable(ctx, RuntimeDetectionKind.SandboxObserved);

        var requests = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        if (fingerprints)
        {
            AntiDebugPass.Request(requests, "KERNEL32.DLL", "GetEnvironmentVariableW");
            AntiDebugPass.Request(requests, "KERNEL32.DLL", "GetModuleHandleW");
        }
        if (humanGate)
        {
            AntiDebugPass.Request(requests, "KERNEL32.DLL", "GetTickCount64");
            AntiDebugPass.Request(requests, "USER32.DLL", "GetLastInputInfo");
        }

        IReadOnlyDictionary<string, uint> iat = requests.Count == 0
            ? new Dictionary<string, uint>(StringComparer.Ordinal)
            : AntiDebugPass.RuntimeImports.Append(ctx, requests);

        if (virtualisation)
            EmitVirtualisationCheck(ctx, iat);
        if (fingerprints)
            EmitFingerprintCheck(ctx, iat);
        if (humanGate)
            EmitHumanActivityCheck(ctx, iat);
    }

    private static void EmitVirtualisationCheck(BuildContext ctx, IReadOnlyDictionary<string, uint> iat)
    {
        RuntimeDetectionStateLayout detectionState = RuntimeDetectionState.Ensure(ctx);
        uint stateRva = ctx.AllocData(40, 8);

        Asm Build(uint selfRva)
        {
            var a = new Asm();
            a.PushR(Reg.Rbx).PushR(Reg.R15);
            a.LoadRuntimeBase(Reg.R15, selfRva).AddRi(Reg.R15, checked((int)detectionState.Rva));

            a.Mov32Ri(Reg.Rax, 1).Cpuid();
            a.MovRr(Reg.R8, Reg.Rcx).AndRi(Reg.R8, unchecked((int)0x80000000));
            a.MovRipStore(Reg.R8, "vm_state", 0);
            a.TestRr(Reg.R8, Reg.R8).Jcc(Cc.E, "vm_done");

            // Hypervisor-present is independently meaningful; leaf 0x40000000
            // supplies the vendor triplet used to cross-check that claim.
            a.Mov32Ri(Reg.Rax, 0x40000000).Cpuid();
            a.MovRipStore(Reg.Rax, "vm_state", 8);
            a.MovRipStore(Reg.Rbx, "vm_state", 16);
            a.MovRipStore(Reg.Rcx, "vm_state", 24);
            a.MovRipStore(Reg.Rdx, "vm_state", 32);
            RuntimeDetectionState.EmitRecord(
                a,
                Reg.R15,
                RuntimeDetectionKind.SandboxObserved,
                taintSession: false,
                taintConstant: 0,
                labelPrefix: "cpuid_vm");

            a.Label("vm_done").PopR(Reg.R15).PopR(Reg.Rbx).Ret();
            a.Align(8).Label("vm_state").Dq(0, 0, 0, 0, 0);
            a.Db(Encoding.ASCII.GetBytes("RMPT.ASBX.CPUID\0"));
            return a;
        }

        uint rva = AntiDebugPass.WriteRoutine(ctx, Build, iat,
            new Dictionary<string, uint> { ["vm_state"] = stateRva });
        ctx.RegisterInit(rva, "CPUID hypervisor and vendor cross-check");
        ctx.Log.Add(new(VirtualisationDetect,
            $"emitted CPUID hypervisor-bit/vendor cross-check at RVA {rva:X8}"));
    }

    private static void EmitFingerprintCheck(BuildContext ctx, IReadOnlyDictionary<string, uint> iat)
    {
        RuntimeDetectionStateLayout detectionState = RuntimeDetectionState.Ensure(ctx);
        uint stateRva = ctx.AllocData(8, 8);
        string[] modules = ["SbieDll.dll", "cuckoomon.dll", "monitor-x64.dll"];
        string[] environmentVariables = ["CUCKOO_ANALYSIS", "SANDBOXIE"];

        Asm Build(uint selfRva)
        {
            var a = new Asm();
            // Shadow space plus a 64-wide-character environment-value buffer.
            a.PushR(Reg.R15).SubRi(Reg.Rsp, 0xA0);
            a.LoadRuntimeBase(Reg.R15, selfRva).AddRi(Reg.R15, checked((int)detectionState.Rva));

            for (int i = 0; i < modules.Length; i++)
            {
                a.LeaRip(Reg.Rcx, $"module_{i}").CallRip("ext::GetModuleHandleW");
                a.TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, $"module_next_{i}");
                a.MovRi(Reg.Rax, i + 1).MovRipStore(Reg.Rax, "fingerprint_state", 0);
                a.Jmp("fingerprint_seen").Label($"module_next_{i}");
            }

            for (int i = 0; i < environmentVariables.Length; i++)
            {
                a.LeaRip(Reg.Rcx, $"environment_{i}");
                a.LeaRd(Reg.Rdx, Reg.Rsp, 0x20);
                a.MovRi(Reg.R8, 64).CallRip("ext::GetEnvironmentVariableW");
                a.TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, $"environment_next_{i}");
                a.MovRi(Reg.Rax, modules.Length + i + 1).MovRipStore(Reg.Rax, "fingerprint_state", 0);
                a.Jmp("fingerprint_seen").Label($"environment_next_{i}");
            }
            a.Jmp("fingerprint_done");

            a.Label("fingerprint_seen");
            RuntimeDetectionState.EmitRecord(
                a,
                Reg.R15,
                RuntimeDetectionKind.SandboxObserved,
                taintSession: false,
                taintConstant: 0,
                labelPrefix: "sandbox_fingerprint");
            a.Label("fingerprint_done").AddRi(Reg.Rsp, 0xA0).PopR(Reg.R15).Ret();

            a.Align(8).Label("fingerprint_state").Dq(0);
            a.Db(Encoding.ASCII.GetBytes("RMPT.ASBX.FINGERPRINT\0"));
            for (int i = 0; i < modules.Length; i++)
                a.Align(2).Label($"module_{i}").Db(Encoding.Unicode.GetBytes(modules[i] + "\0"));
            for (int i = 0; i < environmentVariables.Length; i++)
                a.Align(2).Label($"environment_{i}").Db(Encoding.Unicode.GetBytes(environmentVariables[i] + "\0"));
            AntiDebugPass.AddExternalSlots(a, "GetModuleHandleW", "GetEnvironmentVariableW");
            return a;
        }

        uint rva = AntiDebugPass.WriteRoutine(ctx, Build, iat,
            new Dictionary<string, uint> { ["fingerprint_state"] = stateRva });
        ctx.RegisterInit(rva, "conservative sandbox module and environment fingerprints");
        ctx.Log.Add(new(FingerprintSuite,
            $"emitted {modules.Length} loaded-module and {environmentVariables.Length} environment fingerprints at RVA {rva:X8}"));
    }

    private static void EmitHumanActivityCheck(BuildContext ctx, IReadOnlyDictionary<string, uint> iat)
    {
        RuntimeDetectionStateLayout detectionState = RuntimeDetectionState.Ensure(ctx);
        uint stateRva = ctx.AllocData(32, 8);
        ctx.WriteData(stateRva + 24, BitConverter.GetBytes((ulong)GenerousIdleWindowMilliseconds));

        Asm Build(uint selfRva)
        {
            var a = new Asm();
            a.PushR(Reg.R15).SubRi(Reg.Rsp, 0x30);
            a.LoadRuntimeBase(Reg.R15, selfRva).AddRi(Reg.R15, checked((int)detectionState.Rva));

            // LASTINPUTINFO { cbSize = 8, dwTime = 0 } in local storage.
            a.Mov32Ri(Reg.Rax, 8).MovMr32(Reg.Rsp, Reg.Rax, 0x20);
            a.XorRr(Reg.Rax, Reg.Rax).MovMr32(Reg.Rsp, Reg.Rax, 0x24);
            a.LeaRd(Reg.Rcx, Reg.Rsp, 0x20).CallRip("ext::GetLastInputInfo");
            a.MovRipStore(Reg.Rax, "human_state", 0);
            // API failure supplies no evidence and must not become a detection.
            a.TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "human_done");

            a.CallRip("ext::GetTickCount64");
            a.MovRipStore(Reg.Rax, "human_state", 8);
            // LASTINPUTINFO::dwTime is a wrapping DWORD. Truncate the current
            // tick count before unsigned subtraction so wrap-around is correct.
            a.Db(0x89, 0xC0); // mov eax,eax (zero-extend low tick DWORD)
            a.MovRm32(Reg.Rdx, Reg.Rsp, 0x24).SubRr(Reg.Rax, Reg.Rdx);
            a.MovRipStore(Reg.Rax, "human_state", 16);
            a.MovRi(Reg.Rdx, GenerousIdleWindowMilliseconds).CmpRr(Reg.Rax, Reg.Rdx);
            a.Jcc(Cc.Be, "human_done");
            RuntimeDetectionState.EmitRecord(
                a,
                Reg.R15,
                RuntimeDetectionKind.SandboxObserved,
                taintSession: false,
                taintConstant: 0,
                labelPrefix: "human_idle");

            a.Label("human_done").AddRi(Reg.Rsp, 0x30).PopR(Reg.R15).Ret();
            a.Align(8).Label("human_state").Dq(0, 0, 0, (ulong)GenerousIdleWindowMilliseconds);
            a.Db(Encoding.ASCII.GetBytes("RMPT.ASBX.HUMAN\0"));
            AntiDebugPass.AddExternalSlots(a, "GetLastInputInfo", "GetTickCount64");
            return a;
        }

        uint rva = AntiDebugPass.WriteRoutine(ctx, Build, iat,
            new Dictionary<string, uint> { ["human_state"] = stateRva });
        ctx.RegisterInit(rva, "recent human input observation");
        ctx.Log.Add(new(HumanGate,
            $"emitted GetLastInputInfo gate at RVA {rva:X8} with {GenerousIdleWindowMilliseconds / 60000}-minute idle window"));
    }
}
