using System.Buffers.Binary;
using Rampart.Config;
using Rampart.ControlFlow;
using Rampart.Pe;
using Rampart.X64;

namespace Rampart.Engine.Passes;

/// <summary>Opt-in exception transitions for verified, acyclic integer leaf CFGs.</summary>
public sealed class ExceptionFlowPass
{
    public void Run(BuildContext ctx)
    {
        var sites = new List<ImageExceptionTransition>();
        uint? activeRva = null;
        foreach (var function in ctx.Functions.OrderBy(f => f.BeginRva))
        {
            bool nano = ctx.LevelFor("nuclear.nanomites", function) != ProtectionLevel.Off;
            bool flow = ctx.LevelFor("nuclear.exception-flow", function) != ProtectionLevel.Off;
            if (!nano && !flow) continue;
            nano &= ctx.FunctionPolicy.HasExplicitSelection("nuclear.nanomites", function);
            flow &= ctx.FunctionPolicy.HasExplicitSelection("nuclear.exception-flow", function);
            if (!nano && !flow) { Skip("requires explicit function selection"); continue; }
            if (ctx.IsFunctionClaimed(function)) { Skip("function is owned by an earlier transformation"); continue; }
            if (!LeafFunctionEligibility.TryValidate(ctx, function, out string reason)) { Skip(reason); continue; }
            byte[] original = ctx.Pe.ReadRva(function.BeginRva, (int)function.Size);
            if (!LeafControlFlowCompiler.TryCompileExceptions(original, nano, flow, out var compiled, out reason)) { Skip(reason); continue; }
            if (sites.Count + compiled!.Transitions.Count > 1024) { Skip("build exhausted its 1024 exception-site budget"); continue; }
            activeRva ??= ctx.AllocData(8, 8);
            var a = new Asm();
            // Failure to register the handler leaves the original native CFG
            // reachable. No thread can enter a UD2 path until registration succeeds.
            a.MovRip(Reg.R11, "active").TestRr(Reg.R11, Reg.R11).Jcc(Cc.E, "fallback");
            int bodyOffset = a.Position;
            a.Db(compiled.Code);
            a.Label("fallback").Db(original);
            a.Label("active").Dq(0);
            byte[] code = a.Assemble();
            uint rva = ctx.Alloc(code.Length, 16);
            BuildContext.PatchRipReferences(code, a, rva, new Dictionary<string, uint> { ["active"] = activeRva.Value });
            long displacement = (long)rva - function.BeginRva - 5;
            if (displacement is < int.MinValue or > int.MaxValue) throw new InvalidOperationException("Exception body exceeds direct-branch reach.");
            if (!ctx.TryClaimFunction(function, "exception-flow", rva, (uint)code.Length)) throw new InvalidOperationException("Function ownership changed.");
            ctx.WriteStub(rva, code);
            byte[] jump = new byte[5];
            jump[0] = 0xE9;
            BinaryPrimitives.WriteInt32LittleEndian(jump.AsSpan(1), (int)displacement);
            ctx.Pe.WriteRva(function.BeginRva, jump);
            uint bodyRva = rva + (uint)bodyOffset;
            foreach (var site in compiled.Transitions)
                sites.Add(new(bodyRva + (uint)site.FaultOffset, bodyRva + (uint)site.TakenOffset,
                    bodyRva + (uint)site.FallthroughOffset, site.Condition));
            if (compiled.ConditionalTransitions > 0) ctx.MarkApplied(function, "nuclear.nanomites", ProtectionLevel.Light);
            if (compiled.OtherTransitions > 0) ctx.MarkApplied(function, "nuclear.exception-flow", ProtectionLevel.Light);
            ctx.Log.Add(new("exception-flow", $"rewrote {function.Name} at {function.BeginRva:X8}: " +
                $"{compiled.ConditionalTransitions} dispatched decisions, {compiled.OtherTransitions} exception edges"));

            void Skip(string detail) => ctx.Log.Add(new("exception-flow", $"skipped {function.Name} at {function.BeginRva:X8}: {detail}"));
        }
        if (sites.Count == 0) return;
        uint handlerRva = ctx.Alloc(LeafExceptionDispatcher.Compile(0, sites).Length, 16);
        ctx.WriteStub(handlerRva, LeafExceptionDispatcher.Compile(handlerRva, sites));
        var imports = ImportDirectoryEditor.EnsureNamedImports(ctx, "KERNEL32.DLL", "AddVectoredExceptionHandler");
        var init = new Asm();
        init.SubRi(Reg.Rsp, 40);
        int prologueSize = init.Position;
        init.Mov32Ri(Reg.Rcx, 0).LeaRip(Reg.Rdx, "handler");
        // Register last so application handlers retain their existing order.
        // The executable and its handler stay loaded for the process lifetime.
        init.CallRip("register").MovRipStore(Reg.Rax, "active").AddRi(Reg.Rsp, 40).Ret();
        int codeSize = init.Position;
        init.Label("handler").Dq(0).Label("register").Dq(0).Label("active").Dq(0);
        byte[] initializer = init.Assemble();
        uint initRva = ctx.Alloc(initializer.Length, 16);
        BuildContext.PatchRipReferences(initializer, init, initRva, new Dictionary<string, uint>
        {
            ["handler"] = handlerRva,
            ["register"] = imports["AddVectoredExceptionHandler"],
            ["active"] = activeRva!.Value,
        });
        ctx.WriteStub(initRva, initializer);
        // Calls may unwind through this startup frame. Keep the embedded pointer
        // slots outside its exact code range and describe the 40-byte allocation.
        byte[] unwind = [1, checked((byte)prologueSize), 1, 0,
            checked((byte)prologueSize), 0x42, 0, 0]; // UWOP_ALLOC_SMALL: (4 + 1) * 8 bytes
        ExceptionTableBuilder.Register(ctx, initRva, initRva + (uint)codeSize, unwind);
        ctx.RegisterInit(initRva, "exception-transition handler with native registration-failure fallback");
    }
}
