using System.Text;
using Rampart.X64;

namespace Rampart.Engine.Passes;

/// <summary>
/// Light injection observation. The callback is intentionally separate from
/// the passive anti-debug loader telemetry: it classifies modules loaded after
/// registration against runtime-captured application and Windows-directory
/// prefixes, then records out-of-baseline loads without blocking the loader.
/// </summary>
public sealed class InjectionHunterPass
{
    private const string Knob = "nuclear.injection-hunter";
    private const int MaximumPathCharacters = 260;

    private const int LoadCountOffset = 0;
    private const int AllowedCountOffset = 8;
    private const int ForeignCountOffset = 16;
    private const int LastDllBaseOffset = 24;
    private const int ApplicationPrefixLengthOffset = 32;
    private const int WindowsPrefixLengthOffset = 40;
    private const int RegistrationStatusOffset = 48;
    private const int CookieOffset = 56;
    private const int ApplicationPrefixOffset = 64;
    private const int WindowsPrefixOffset = ApplicationPrefixOffset + MaximumPathCharacters * 2;

    public void Run(BuildContext ctx)
    {
        if (ctx.Level(Knob) == Config.ProtectionLevel.Off)
            return;

        RuntimeDetectionState.Enable(ctx, RuntimeDetectionKind.ForeignModuleObserved);
        RuntimeDetectionStateLayout detectionState = RuntimeDetectionState.Ensure(ctx);

        var requests = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        AntiDebugPass.Request(requests, "KERNEL32.DLL", "GetModuleFileNameW");
        AntiDebugPass.Request(requests, "KERNEL32.DLL", "GetWindowsDirectoryW");
        AntiDebugPass.Request(requests, "NTDLL.DLL", "LdrRegisterDllNotification");
        IReadOnlyDictionary<string, uint> iat = AntiDebugPass.RuntimeImports.Append(ctx, requests);

        uint callbackRva = EmitClassifierCallback(ctx, iat, detectionState, out uint callbackStateRva);
        EmitRegistration(ctx, iat, callbackRva, callbackStateRva);
    }

    private static uint EmitClassifierCallback(
        BuildContext ctx,
        IReadOnlyDictionary<string, uint> iat,
        RuntimeDetectionStateLayout detectionState,
        out uint callbackStateRva)
    {
        int stateSize = WindowsPrefixOffset + MaximumPathCharacters * 2;
        callbackStateRva = ctx.AllocData(stateSize, 16);

        Asm Build(uint selfRva)
        {
            var a = new Asm();
            // Preserve every nonvolatile register used by the two prefix walks.
            a.PushR(Reg.Rbx).PushR(Reg.Rsi).PushR(Reg.Rdi).PushR(Reg.R12);
            a.PushR(Reg.R13).PushR(Reg.R14).PushR(Reg.R15);
            a.MovRr(Reg.R12, Reg.Rcx); // notification reason
            a.MovRr(Reg.R11, Reg.Rdx); // notification data (no calls below)
            a.LoadRuntimeBase(Reg.R15, selfRva);
            a.MovRr(Reg.R14, Reg.R15).AddRi(Reg.R14, checked((int)detectionState.Rva));
            a.LeaRip(Reg.R13, "hunter_state");

            // LDR_DLL_NOTIFICATION_REASON_LOADED is 1; unloads do not create
            // new foreign code and are therefore left as passive telemetry.
            a.MovRi(Reg.Rax, 1).CmpRr(Reg.R12, Reg.Rax).Jcc(Cc.Ne, "hunter_done");
            a.MovRm(Reg.Rax, Reg.R13, LoadCountOffset).IncR(Reg.Rax);
            a.MovMr(Reg.R13, Reg.Rax, LoadCountOffset);

            // Loaded.FullDllName is a PCUNICODE_STRING at notification-data +8.
            a.MovRm(Reg.Rbx, Reg.R11, 8).TestRr(Reg.Rbx, Reg.Rbx).Jcc(Cc.E, "foreign_load");
            a.MovRm32(Reg.R9, Reg.Rbx, 0).AndRi(Reg.R9, 0xFFFF).ShrRi(Reg.R9, 1);
            a.TestRr(Reg.R9, Reg.R9).Jcc(Cc.E, "foreign_load");
            a.MovRm(Reg.R10, Reg.Rbx, 8).TestRr(Reg.R10, Reg.R10).Jcc(Cc.E, "foreign_load");
            a.MovRm(Reg.Rax, Reg.R11, 24).MovMr(Reg.R13, Reg.Rax, LastDllBaseOffset);

            EmitPrefixMatch(
                a,
                ApplicationPrefixLengthOffset,
                ApplicationPrefixOffset,
                "application_prefix",
                "check_windows_prefix");
            a.Label("check_windows_prefix");
            EmitPrefixMatch(
                a,
                WindowsPrefixLengthOffset,
                WindowsPrefixOffset,
                "windows_prefix",
                "foreign_load");

            a.Label("allowed_load");
            a.MovRm(Reg.Rax, Reg.R13, AllowedCountOffset).IncR(Reg.Rax);
            a.MovMr(Reg.R13, Reg.Rax, AllowedCountOffset).Jmp("hunter_done");

            a.Label("foreign_load");
            a.MovRm(Reg.Rax, Reg.R13, ForeignCountOffset).IncR(Reg.Rax);
            a.MovMr(Reg.R13, Reg.Rax, ForeignCountOffset);
            RuntimeDetectionState.EmitRecord(
                a,
                Reg.R14,
                RuntimeDetectionKind.ForeignModuleObserved,
                taintSession: false,
                taintConstant: 0,
                labelPrefix: "foreign_module");

            a.Label("hunter_done").XorRr(Reg.Rax, Reg.Rax);
            a.PopR(Reg.R15).PopR(Reg.R14).PopR(Reg.R13).PopR(Reg.R12);
            a.PopR(Reg.Rdi).PopR(Reg.Rsi).PopR(Reg.Rbx).Ret();

            a.Align(16).Label("hunter_state");
            a.Dq(0, 0, 0, 0, 0, 0, 0, 0);
            a.Db(new byte[MaximumPathCharacters * 2]);
            a.Db(new byte[MaximumPathCharacters * 2]);
            a.Db(Encoding.ASCII.GetBytes("RMPT.INJECT.HUNTER\0"));
            return a;
        }

        uint callbackRva = AntiDebugPass.WriteRoutine(ctx, Build, iat,
            new Dictionary<string, uint> { ["hunter_state"] = callbackStateRva });
        GuardCfBuilder.RegisterTarget(ctx, callbackRva);
        return callbackRva;
    }

    /// <summary>
    /// Compares FullDllName (R10, R9 characters) with one captured UTF-16
    /// prefix. ASCII letters are case-folded; punctuation and non-ASCII code
    /// units must match exactly, which biases unusual paths toward detection.
    /// </summary>
    private static void EmitPrefixMatch(
        Asm a,
        int lengthOffset,
        int bufferOffset,
        string labelPrefix,
        string noMatchLabel)
    {
        a.MovRm(Reg.Rbx, Reg.R13, lengthOffset);
        a.TestRr(Reg.Rbx, Reg.Rbx).Jcc(Cc.E, noMatchLabel);
        a.CmpRr(Reg.R9, Reg.Rbx).Jcc(Cc.B, noMatchLabel);
        a.MovRr(Reg.Rsi, Reg.R10).LeaRd(Reg.Rdi, Reg.R13, bufferOffset);
        a.Label($"{labelPrefix}_loop");
        a.TestRr(Reg.Rbx, Reg.Rbx).Jcc(Cc.E, "allowed_load");

        // Compare the high bytes first. If the code unit is non-ASCII, the
        // exact low-byte comparison below is the only accepted match.
        a.XorRr(Reg.Rcx, Reg.Rcx).MovRm8(Reg.Rcx, Reg.Rsi, 1);
        a.XorRr(Reg.R8, Reg.R8).MovRm8(Reg.R8, Reg.Rdi, 1);
        a.CmpRr(Reg.Rcx, Reg.R8).Jcc(Cc.Ne, noMatchLabel);
        a.XorRr(Reg.Rax, Reg.Rax).MovRm8(Reg.Rax, Reg.Rsi);
        a.XorRr(Reg.Rdx, Reg.Rdx).MovRm8(Reg.Rdx, Reg.Rdi);
        a.CmpRr(Reg.Rax, Reg.Rdx).Jcc(Cc.E, $"{labelPrefix}_matched");
        a.TestRr(Reg.Rcx, Reg.Rcx).Jcc(Cc.Ne, noMatchLabel);

        // A simple bit clear folds ASCII letters, but it also aliases some
        // punctuation pairs. Accept the folded match only when it lands in A-Z.
        a.AndRi(Reg.Rax, 0xDF).AndRi(Reg.Rdx, 0xDF);
        a.CmpRr(Reg.Rax, Reg.Rdx).Jcc(Cc.Ne, noMatchLabel);
        a.MovRi(Reg.Rcx, 'A').CmpRr(Reg.Rax, Reg.Rcx).Jcc(Cc.B, noMatchLabel);
        a.MovRi(Reg.Rcx, 'Z').CmpRr(Reg.Rax, Reg.Rcx).Jcc(Cc.A, noMatchLabel);
        a.Label($"{labelPrefix}_matched");
        a.AddRi(Reg.Rsi, 2).AddRi(Reg.Rdi, 2).DecR(Reg.Rbx);
        a.Jmp($"{labelPrefix}_loop");
    }

    private static void EmitRegistration(
        BuildContext ctx,
        IReadOnlyDictionary<string, uint> iat,
        uint callbackRva,
        uint callbackStateRva)
    {
        Asm Build(uint selfRva)
        {
            var a = new Asm();
            a.PushR(Reg.Rbx).PushR(Reg.R12).PushR(Reg.R13).PushR(Reg.R14).PushR(Reg.R15);
            a.SubRi(Reg.Rsp, 0x20);
            a.LoadRuntimeBase(Reg.R15, selfRva);
            a.MovRi(Reg.R13, callbackStateRva).AddRr(Reg.R13, Reg.R15);

            // Capture the executable's runtime directory, including its final
            // separator, so ordinary sibling DLL/plugin loads remain trusted.
            a.LeaRd(Reg.R14, Reg.R13, ApplicationPrefixOffset);
            a.XorRr(Reg.Rcx, Reg.Rcx).MovRr(Reg.Rdx, Reg.R14);
            a.MovRi(Reg.R8, MaximumPathCharacters).CallRip("ext::GetModuleFileNameW");
            a.TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "application_prefix_done");
            a.MovRi(Reg.Rdx, MaximumPathCharacters).CmpRr(Reg.Rax, Reg.Rdx);
            a.Jcc(Cc.Ae, "application_prefix_done");
            a.MovRr(Reg.Rbx, Reg.R14).MovRr(Reg.Rcx, Reg.Rax).ShlRi(Reg.Rcx, 1).AddRr(Reg.Rbx, Reg.Rcx);
            a.Label("application_prefix_scan");
            a.CmpRr(Reg.Rbx, Reg.R14).Jcc(Cc.E, "application_prefix_done");
            a.SubRi(Reg.Rbx, 2).XorRr(Reg.Rdx, Reg.Rdx).MovRm8(Reg.Rdx, Reg.Rbx);
            a.MovRi(Reg.Rcx, '\\').CmpRr(Reg.Rdx, Reg.Rcx).Jcc(Cc.Ne, "application_prefix_scan");
            a.MovRr(Reg.Rax, Reg.Rbx).SubRr(Reg.Rax, Reg.R14).ShrRi(Reg.Rax, 1).IncR(Reg.Rax);
            a.MovMr(Reg.R13, Reg.Rax, ApplicationPrefixLengthOffset);
            a.Label("application_prefix_done");

            // WindowsDirectory does not normally include a trailing separator;
            // append one so C:\\WindowsEvil cannot satisfy the allow prefix.
            a.LeaRd(Reg.R14, Reg.R13, WindowsPrefixOffset).MovRr(Reg.Rcx, Reg.R14);
            a.MovRi(Reg.Rdx, MaximumPathCharacters - 1).CallRip("ext::GetWindowsDirectoryW");
            a.TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "windows_prefix_done");
            a.MovRi(Reg.Rdx, MaximumPathCharacters - 2).CmpRr(Reg.Rax, Reg.Rdx);
            a.Jcc(Cc.A, "windows_prefix_done");
            a.MovRr(Reg.Rbx, Reg.R14).MovRr(Reg.Rdx, Reg.Rax).ShlRi(Reg.Rdx, 1).AddRr(Reg.Rbx, Reg.Rdx);
            a.MovRi(Reg.Rcx, '\\').MovMr8(Reg.Rbx, Reg.Rcx);
            a.IncR(Reg.Rax).MovMr(Reg.R13, Reg.Rax, WindowsPrefixLengthOffset);
            a.Label("windows_prefix_done");

            a.XorRr(Reg.Rcx, Reg.Rcx);
            a.MovRi(Reg.Rdx, callbackRva).AddRr(Reg.Rdx, Reg.R15);
            a.XorRr(Reg.R8, Reg.R8).LeaRd(Reg.R9, Reg.R13, CookieOffset);
            a.CallRip("ext::LdrRegisterDllNotification");
            a.MovMr(Reg.R13, Reg.Rax, RegistrationStatusOffset);

            a.AddRi(Reg.Rsp, 0x20).PopR(Reg.R15).PopR(Reg.R14).PopR(Reg.R13);
            a.PopR(Reg.R12).PopR(Reg.Rbx).Ret();
            AntiDebugPass.AddExternalSlots(
                a,
                "GetModuleFileNameW",
                "GetWindowsDirectoryW",
                "LdrRegisterDllNotification");
            return a;
        }

        uint initRva = AntiDebugPass.WriteRoutine(ctx, Build, iat);
        ctx.RegisterInit(initRva, "post-start foreign-module classifier");
        ctx.Log.Add(new(Knob,
            $"emitted loader classifier at RVA {callbackRva:X8}; runtime application/Windows allowlist captured by RVA {initRva:X8}"));
    }
}
