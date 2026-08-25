using System.Text;
using Rampart.X64;

namespace Rampart.Engine.Passes;

/// <summary>
/// Starts a genuine monitor worker and applies ThreadHideFromDebugger to that
/// worker. The monitor remains behavior-neutral: it periodically records the
/// PEB debugger signal in shared state and never terminates or delays the host.
/// </summary>
public sealed class HiddenThreadsPass
{
    private const string Knob = "integrity.hidden-threads";
    private const int ThreadHideFromDebugger = 0x11;
    private const int MonitorIntervalMilliseconds = 5_000;

    public void Run(BuildContext ctx)
    {
        if (ctx.Level(Knob) == Config.ProtectionLevel.Off)
            return;

        RuntimeDetectionState.Enable(ctx, RuntimeDetectionKind.DebuggerObserved);
        RuntimeDetectionStateLayout detectionState = RuntimeDetectionState.Ensure(ctx);

        var requests = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        AntiDebugPass.Request(requests, "KERNEL32.DLL", "CloseHandle");
        AntiDebugPass.Request(requests, "KERNEL32.DLL", "CreateThread");
        AntiDebugPass.Request(requests, "KERNEL32.DLL", "Sleep");
        AntiDebugPass.Request(requests, "NTDLL.DLL", "NtSetInformationThread");
        IReadOnlyDictionary<string, uint> iat = AntiDebugPass.RuntimeImports.Append(ctx, requests);

        uint workerRva = EmitWorker(ctx, iat, detectionState);
        GuardCfBuilder.RegisterTarget(ctx, workerRva);
        EmitLauncher(ctx, iat, workerRva);
    }

    private static uint EmitWorker(
        BuildContext ctx,
        IReadOnlyDictionary<string, uint> iat,
        RuntimeDetectionStateLayout detectionState)
    {
        uint workerStateRva = ctx.AllocData(32, 8);
        ctx.WriteData(workerStateRva + 24, BitConverter.GetBytes((ulong)MonitorIntervalMilliseconds));
        Asm Build(uint selfRva)
        {
            var a = new Asm();
            // Two saves and 0x28 bytes align every API call while retaining the
            // standard four-register shadow space.
            a.PushR(Reg.Rbx).PushR(Reg.R15).SubRi(Reg.Rsp, 0x28);
            a.LoadRuntimeBase(Reg.R15, selfRva).AddRi(Reg.R15, checked((int)detectionState.Rva));

            // NtCurrentThread is the stable -2 pseudo-handle. No payload is
            // required for ThreadHideFromDebugger.
            a.MovRi(Reg.Rcx, -2).MovRi(Reg.Rdx, ThreadHideFromDebugger);
            a.XorRr(Reg.R8, Reg.R8).XorRr(Reg.R9, Reg.R9);
            a.CallRip("ext::NtSetInformationThread");
            a.MovRipStore(Reg.Rax, "worker_state", 0);

            a.Label("monitor_loop");
            a.MovRip(Reg.Rax, "worker_state", 8).IncR(Reg.Rax);
            a.MovRipStore(Reg.Rax, "worker_state", 8);
            a.MovRegPeb(Reg.Rbx).XorRr(Reg.Rax, Reg.Rax).MovRm8(Reg.Rax, Reg.Rbx, 2);
            a.TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "monitor_sleep");
            a.MovRip(Reg.Rax, "worker_state", 16).IncR(Reg.Rax);
            a.MovRipStore(Reg.Rax, "worker_state", 16);
            RuntimeDetectionState.EmitRecord(
                a,
                Reg.R15,
                RuntimeDetectionKind.DebuggerObserved,
                taintSession: false,
                taintConstant: 0,
                labelPrefix: "hidden_thread_debug");
            a.Label("monitor_sleep").MovRi(Reg.Rcx, MonitorIntervalMilliseconds);
            a.CallRip("ext::Sleep").Jmp("monitor_loop");

            a.Align(8).Label("worker_state").Dq(0, 0, 0, (ulong)MonitorIntervalMilliseconds);
            a.Db(Encoding.ASCII.GetBytes("RMPT.HIDDEN.THREAD\0"));
            AntiDebugPass.AddExternalSlots(a, "NtSetInformationThread", "Sleep");
            return a;
        }

        return AntiDebugPass.WriteRoutine(ctx, Build, iat,
            new Dictionary<string, uint> { ["worker_state"] = workerStateRva });
    }

    private static void EmitLauncher(
        BuildContext ctx,
        IReadOnlyDictionary<string, uint> iat,
        uint workerRva)
    {
        uint launcherStateRva = ctx.AllocData(24, 8);
        Asm Build(uint selfRva)
        {
            var a = new Asm();
            a.PushR(Reg.R15).SubRi(Reg.Rsp, 0x40);
            a.LoadRuntimeBase(Reg.R15, selfRva);

            // CreateThread(NULL, 0, worker, NULL, 0, &threadId). The worker does
            // not need a retained kernel handle, so close it after creation.
            a.XorRr(Reg.Rax, Reg.Rax).MovMr(Reg.Rsp, Reg.Rax, 0x20);
            a.LeaRd(Reg.Rax, Reg.Rsp, 0x30).MovMr(Reg.Rsp, Reg.Rax, 0x28);
            a.XorRr(Reg.Rcx, Reg.Rcx).XorRr(Reg.Rdx, Reg.Rdx);
            a.MovRi(Reg.R8, workerRva).AddRr(Reg.R8, Reg.R15);
            a.XorRr(Reg.R9, Reg.R9).CallRip("ext::CreateThread");
            a.MovRipStore(Reg.Rax, "launcher_state", 0);
            a.TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "launcher_done");
            a.MovMr(Reg.Rsp, Reg.Rax, 0x38);

            // Hide synchronously through the new thread handle as well as from
            // inside the worker. This proves the protection is applied even if
            // the host reaches ExitProcess before the worker gets scheduled.
            a.MovRr(Reg.Rcx, Reg.Rax).MovRi(Reg.Rdx, ThreadHideFromDebugger);
            a.XorRr(Reg.R8, Reg.R8).XorRr(Reg.R9, Reg.R9);
            a.CallRip("ext::NtSetInformationThread");
            a.MovRipStore(Reg.Rax, "launcher_state", 8);
            a.MovRm(Reg.Rcx, Reg.Rsp, 0x38).CallRip("ext::CloseHandle");
            a.MovRipStore(Reg.Rax, "launcher_state", 16);

            a.Label("launcher_done").AddRi(Reg.Rsp, 0x40).PopR(Reg.R15).Ret();
            a.Align(8).Label("launcher_state").Dq(0, 0, 0);
            a.Db(Encoding.ASCII.GetBytes("RMPT.HIDDEN.LAUNCHER\0"));
            AntiDebugPass.AddExternalSlots(a, "CreateThread", "NtSetInformationThread", "CloseHandle");
            return a;
        }

        uint initRva = AntiDebugPass.WriteRoutine(ctx, Build, iat,
            new Dictionary<string, uint> { ["launcher_state"] = launcherStateRva });
        ctx.RegisterInit(initRva, "hidden debugger-monitor worker launch");
        ctx.Log.Add(new(Knob,
            $"emitted ThreadHideFromDebugger monitor at RVA {workerRva:X8} and launcher at RVA {initRva:X8}"));
    }
}
