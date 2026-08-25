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

        var a = new Asm();
        // The dispatcher is also the TLS callback target: it runs the init chain
        // before the entry point. A guard word makes re-entry per-thread a no-op.
        uint guardRva = ctx.AllocData(8, 8);
        uint dispatcherRva = ctx.Alloc(EstimateDispatcherSize(ctx), 16);
        EmitDispatcher(ctx, a, dispatcherRva, originalEp);
        byte[] dispatcher = a.Assemble();
        BuildContext.PatchRipReferences(dispatcher, a, dispatcherRva,
            new Dictionary<string, uint> { ["guard"] = guardRva });
        ctx.WriteStub(dispatcherRva, dispatcher);
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

        // The new entry point: a misaligned-instruction gem that funnels into a
        // jump to OEP. Execution starts at gem+0 by construction; a disassembler
        // linear-sweeping from the section start falls into the overlapping bytes.
        var g = new Asm();
        uint gemRva = ctx.Alloc(64, 16);
        g.Label("gem");
        g.CallRva(gemRva, dispatcherRva);
        // Overlap pair: entering at +0 vs +1 decodes differently (the EB skips
        // into the middle of the next instruction).
        g.Db(0xEB, 0x10);                       // jmp +0x10 → over the confusion field
        for (int i = 0; i < 0x10; i++)
            g.Db((byte)ctx.Rng.Next(0x00, 0x100)); // noise: invalid/misleading opcodes
        g.Label("real_path");
        // Only reachable via the jmp above — and via nothing else.
        if (guardCf)
            g.JmpRva(gemRva, originalEp);
        else
        {
            g.JmpRip("oep_slot");
            g.Align(8);
            g.Label("oep_slot");
            g.Dq(pe.ImageBase + originalEp);        // patched below; reloc registered
        }
        byte[] gem = g.Assemble();
        ctx.WriteStub(gemRva, gem);
        if (guardCf)
            GuardCfBuilder.RegisterTarget(ctx, gemRva);

        // Store OEP as an absolute VA in the slot (ASLR: DIR64 relocation).
        if (!guardCf)
        {
            int oepSlotOff = g.LabelOffset("oep_slot");
            ctx.WriteStub(gemRva + (uint)oepSlotOff, BitConverter.GetBytes(pe.ImageBase + originalEp));
            ctx.RelocSlots.Add(gemRva + (uint)oepSlotOff);
        }

        pe.EntryPointRva = gemRva;
        ctx.Log.Add(new("ep-confusion",
            $"entry rerouted to gem at {gemRva:X8}; OEP {originalEp:X8} reached via " +
            $"{(guardCf ? "direct CFG-compatible transfer" : "indirect slot")}; " +
            $"dispatcher at {dispatcherRva:X8} ({(guardCf ? "entry-direct" : "TLS + entry guard")})"));
    }

    /// <summary>The dispatcher walks the registered init chain, each entry a
    /// function taking no arguments, returning void, ABI-compliant. A guard word
    /// makes later thread-start invocations no-ops.</summary>
    private static void EmitDispatcher(BuildContext ctx, Asm a, uint selfRva, uint originalEp)
    {
        // Snapshot the chain WITHOUT the dispatcher itself — registering the
        // dispatcher happens after emission and must not recurse into its own walk.
        var chain = ctx.InitChain.ToList();

        a.Label("disp_start");
        a.PushR(Reg.Rbx);
        a.PushR(Reg.Rdi);
        a.PushR(Reg.Rsi);
        a.PushR(Reg.R12);
        a.SubRi(Reg.Rsp, 8);            // 5 pushes/sub total keeps calls 16-aligned

        // Guard: first invocation runs the chain, later thread starts are no-ops.
        a.MovRip(Reg.Rax, "guard");     // mov rax, [rip+guard]
        a.TestRr(Reg.Rax, Reg.Rax);
        a.Jcc(Cc.Ne, "done");
        a.MovRi(Reg.Rax, 1);
        a.MovRipStore(Reg.Rax, "guard");

        a.MovRi(Reg.R12, chain.Count);
        a.LeaRip(Reg.Rbx, "chain");
        a.Label("next");
        a.TestRr(Reg.R12, Reg.R12);
        a.Jcc(Cc.E, "done");
        a.MovRm(Reg.Rax, Reg.Rbx, 0);
        a.TestRr(Reg.Rax, Reg.Rax);
        a.Jcc(Cc.E, "skip");
        a.CallReg(Reg.Rax);
        a.Label("skip");
        a.AddRi(Reg.Rbx, 8);
        a.DecR(Reg.R12);
        a.Jmp("next");

        a.Label("done");
        a.AddRi(Reg.Rsp, 8);
        a.PopR(Reg.R12);
        a.PopR(Reg.Rsi);
        a.PopR(Reg.Rdi);
        a.PopR(Reg.Rbx);
        a.Ret();

        a.Align(8);
        a.Label("guard");
        a.Dq(0);
        a.Label("chain");
        foreach (uint rva in chain)
            a.Dq(ctx.Pe.ImageBase + rva);
        a.Dq(0);

        // The chain holds absolute VAs: every slot needs a DIR64 relocation.
        int chainOff = a.LabelOffset("chain");
        for (int i = 0; i < chain.Count; i++)
            ctx.RelocSlots.Add(selfRva + (uint)(chainOff + i * 8));
    }

    private static int EstimateDispatcherSize(BuildContext ctx) =>
        160 + (ctx.InitChain.Count + 2) * 8;
}
