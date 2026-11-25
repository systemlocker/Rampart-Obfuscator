using Rampart.Pe;
using Rampart.X64;

namespace Rampart.Engine.Passes;

/// <summary>Entry-point confusion: the entry becomes a protector stub that (via
/// TLS) has already run the init chain, walks an overlapping-instruction gem —
/// bytes that decode differently depending on entry offset, so linear sweeps
/// desynchronize — and only then jumps to the original entry point.</summary>
public sealed class EntryPointPass
{
    public void Run(BuildContext ctx)
    {
        var level = ctx.Level("packaging.ep-confusion");
        if (level == Config.ProtectionLevel.Off)
            return;
        var pe = ctx.Pe;
        uint originalEp = pe.EntryPointRva;

        // The dispatcher is also the TLS callback target: it runs the init chain
        // before the entry point. The atomic owner-token latch serializes concurrent
        // threads while allowing same-thread TLS re-entry to return immediately.
        uint guardRva = ctx.AllocData(8, 8);
        var chain = ctx.InitChain.ToList();

        AntiDebugPass.BuiltRoutine BuildDispatcher()
        {
            var a = new Asm();
            var pushes = new List<(Reg, byte)>();
            foreach (Reg reg in new[] { Reg.Rbx, Reg.Rdi, Reg.Rsi, Reg.R12 })
            {
                a.PushR(reg);
                pushes.Add((reg, (byte)a.Position));
            }
            // Four saved registers leave the entry alignment unchanged. Initializers
            // may spill arguments into their caller-provided 32-byte home area.
            a.SubRi(Reg.Rsp, 0x28);
            byte prologEnd = (byte)a.Position;

            // Atomic 3-state re-entrant initialization latch:
            //   0               = idle
            //   (tid << 1) | 1  = running on thread `tid` (never 0 or -1)
            //   -1              = done
            // Storing the owning thread token lets same-thread re-entry (such as
            // ExitProcess firing TLS DLL_PROCESS_DETACH while a startup check is
            // running) return immediately instead of self-deadlocking, while other
            // threads still spin until initialization publishes -1.
            a.LeaRip(Reg.Rcx, "guard");
            a.Db(0x65, 0x8B, 0x14, 0x25, 0x48, 0x00, 0x00, 0x00); // mov edx, gs:[0x48] (TEB.ClientId.UniqueThread)
            a.AddRr(Reg.Rdx, Reg.Rdx);
            a.IncR(Reg.Rdx);
            a.Label("guard_spin");
            a.XorRr(Reg.Rax, Reg.Rax);
            a.Db(0xF0, 0x48, 0x0F, 0xB1, 0x11); // lock cmpxchg qword ptr [rcx], rdx
            a.Jcc(Cc.E, "run_chain");
            a.CmpRr(Reg.Rax, Reg.Rdx);
            a.Jcc(Cc.E, "done");
            a.IncR(Reg.Rax);
            a.Jcc(Cc.E, "done");
            a.Db(0xF3, 0x90); // pause
            a.Jmp("guard_spin");

            a.Label("run_chain");
            a.MovRi(Reg.R12, chain.Count);
            a.LeaRip(Reg.Rbx, "chain");
            a.Label("next");
            a.TestRr(Reg.R12, Reg.R12);
            a.Jcc(Cc.E, "publish_done");
            a.MovRm(Reg.Rax, Reg.Rbx, 0);
            a.TestRr(Reg.Rax, Reg.Rax);
            a.Jcc(Cc.E, "skip");
            a.CallReg(Reg.Rax);
            a.Label("skip");
            a.AddRi(Reg.Rbx, 8);
            a.DecR(Reg.R12);
            a.Jmp("next");

            a.Label("publish_done");
            a.LeaRip(Reg.Rcx, "guard");
            a.MovRi(Reg.Rax, -1);
            a.Db(0x48, 0x87, 0x01); // xchg [rcx], rax (full memory barrier)

            a.Label("done");
            a.AddRi(Reg.Rsp, 0x28);
            a.PopR(Reg.R12);
            a.PopR(Reg.Rsi);
            a.PopR(Reg.Rdi);
            a.PopR(Reg.Rbx);
            a.Ret();
            int codeEnd = a.Position;

            // "guard" is patched to .rmpd via PatchRipReferences; no local slot is needed.
            a.Label("guard");
            a.AlignData(8);
            a.Label("chain");
            foreach (uint rva in chain)
                a.Dq(pe.ImageBase + rva);
            a.Dq(0);
            return new AntiDebugPass.BuiltRoutine(a, codeEnd, AntiDebugPass.BuildUnwindInfo(pushes, 0x28, prologEnd));
        }

        int dispatcherSize = BuildDispatcher().Assembler.Assemble().Length;
        uint dispatcherRva = ctx.Alloc(dispatcherSize, 16);
        AntiDebugPass.BuiltRoutine builtDispatcher = BuildDispatcher();
        byte[] dispatcher = builtDispatcher.Assembler.Assemble();
        if (dispatcher.Length != dispatcherSize)
            throw new InvalidOperationException("Init dispatcher size shifted between layout passes.");
        BuildContext.PatchRipReferences(dispatcher, builtDispatcher.Assembler, dispatcherRva,
            new Dictionary<string, uint> { ["guard"] = guardRva });
        int chainOff = builtDispatcher.Assembler.LabelOffset("chain");
        for (int i = 0; i < chain.Count; i++)
            ctx.RelocSlots.Add(checked(dispatcherRva + (uint)(chainOff + i * 8)));
        ctx.WriteStub(dispatcherRva, dispatcher);
        ExceptionTableBuilder.Register(ctx, dispatcherRva, checked(dispatcherRva + (uint)builtDispatcher.CodeEnd), builtDispatcher.UnwindInfo!);
        ctx.RegisterInit(dispatcherRva, "init dispatcher (string decrypt + import resolve chain)");

        bool guardCf = PeCompatibility.Inspect(pe).GuardCf;
        if (!guardCf)
        {
            TlsBuilder.Install(ctx, dispatcherRva);
        }
        else
        {
            // CFG-aware Windows loaders invoke TLS callbacks through guarded
            // dispatch. Rather than weakening CFG or mutating all related
            // metadata, run the init chain by a direct call from the new entry.
            // Existing target TLS callbacks remain byte-for-byte untouched.
            ctx.Log.Add(new("guard-cf", "preserved Guard CF metadata; startup initialization routed through the entry point"));
        }

        // The new entry point: a misaligned-instruction gem that preserves incoming
        // entry arguments across the dispatcher call, walks an overlapping-instruction
        // confusion field, and transfers to the original entry point.
        byte[] noise = new byte[0x10];
        ctx.Rng.NextBytes(noise);

        AntiDebugPass.BuiltRoutine BuildGem(uint selfRva)
        {
            var g = new Asm();
            g.Label("gem");
            // Entry RSP is 8 mod 16. Allocating 0x48 bytes restores 16-byte alignment,
            // provides 0x20 bytes of callee home space, and reserves [rsp+0x20..0x3F]
            // to preserve incoming RCX/RDX/R8/R9 across the dispatcher call.
            g.SubRi(Reg.Rsp, 0x48);
            byte prologEnd = (byte)g.Position;
            g.MovMr(Reg.Rsp, Reg.Rcx, 0x20);
            g.MovMr(Reg.Rsp, Reg.Rdx, 0x28);
            g.MovMr(Reg.Rsp, Reg.R8, 0x30);
            g.MovMr(Reg.Rsp, Reg.R9, 0x38);
            g.CallRva(selfRva, dispatcherRva);
            g.MovRm(Reg.Rcx, Reg.Rsp, 0x20);
            g.MovRm(Reg.Rdx, Reg.Rsp, 0x28);
            g.MovRm(Reg.R8, Reg.Rsp, 0x30);
            g.MovRm(Reg.R9, Reg.Rsp, 0x38);
            g.AddRi(Reg.Rsp, 0x48);
            // Overlap pair: entering at +0 vs +1 decodes differently (the EB skips
            // into the middle of the next instruction).
            g.Db(0xEB, 0x10);
            g.Db(noise);
            g.Label("real_path");
            if (guardCf)
                g.JmpRva(selfRva, originalEp);
            else
                g.JmpRip("oep_slot");
            int codeEnd = g.Position;
            if (!guardCf)
            {
                g.AlignData(8);
                g.Label("oep_slot");
                g.Dq(pe.ImageBase + originalEp);
            }
            return new AntiDebugPass.BuiltRoutine(g, codeEnd, AntiDebugPass.BuildUnwindInfo([], 0x48, prologEnd));
        }

        int gemSize = BuildGem(0).Assembler.Assemble().Length;
        uint gemRva = ctx.Alloc(gemSize, 16);
        AntiDebugPass.BuiltRoutine builtGem = BuildGem(gemRva);
        byte[] gem = builtGem.Assembler.Assemble();
        if (gem.Length != gemSize)
            throw new InvalidOperationException("Entry gem size shifted between layout passes.");
        ctx.WriteStub(gemRva, gem);
        ExceptionTableBuilder.Register(ctx, gemRva, checked(gemRva + (uint)builtGem.CodeEnd), builtGem.UnwindInfo!);
        if (guardCf)
            GuardCfBuilder.RegisterTarget(ctx, gemRva);

        // Store OEP as an absolute VA in the slot (ASLR: DIR64 relocation).
        if (!guardCf)
        {
            int oepSlotOff = builtGem.Assembler.LabelOffset("oep_slot");
            ctx.WriteStub(checked(gemRva + (uint)oepSlotOff), BitConverter.GetBytes(pe.ImageBase + originalEp));
            ctx.RelocSlots.Add(checked(gemRva + (uint)oepSlotOff));
        }

        pe.EntryPointRva = gemRva;
        ctx.Log.Add(new("ep-confusion",
            $"entry rerouted to gem at {gemRva:X8}; OEP {originalEp:X8} reached via " +
            $"{(guardCf ? "direct CFG-compatible transfer" : "indirect slot")}; " +
            $"dispatcher at {dispatcherRva:X8} ({(guardCf ? "entry-direct" : "TLS + entry guard")})"));
    }
}
