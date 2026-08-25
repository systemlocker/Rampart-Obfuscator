using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Text;
using Rampart.X64;

namespace Rampart.Engine;

/// <summary>Reasons recorded by Rampart's runtime checks. The state is deliberately
/// data-only: detection producers can share it without depending on one another,
/// and response emitters can consume the same flags.</summary>
[Flags]
public enum RuntimeDetectionKind : ulong
{
    None = 0,
    CodeModified = 1UL << 0,
    IatModified = 1UL << 1,
    TlsOwnershipLost = 1UL << 2,
    MitigationRejected = 1UL << 3,
    DebuggerObserved = 1UL << 4,
    SandboxObserved = 1UL << 5,
    ForeignModuleObserved = 1UL << 6,
    SentinelModified = 1UL << 7,
}

/// <summary>Location of the shared record emitted into <c>.rmpd</c>.</summary>
public sealed record RuntimeDetectionStateLayout(uint Rva, ulong InitialSessionKey)
{
    public const int MagicOffset = 0;
    public const int VersionOffset = 8;
    public const int SizeOffset = 12;
    public const int EnabledChecksOffset = 16;
    public const int DetectionFlagsOffset = 24;
    public const int SessionKeyOffset = 32;
    public const int CodeMeasurementOffset = 40;
    public const int IatBaselineOffset = 48;
    public const int PolicyStatusOffset = 56;
    public const int RespondedFlagsOffset = 64;
    public const int TlsCallbacksRvaOffset = 72;
    public const int RecordSize = 80;
}

/// <summary>Allocates and updates a single shared runtime-detection record for a
/// build. A weak table keeps the API additive and avoids coupling BuildContext to
/// individual guard modules.</summary>
public static class RuntimeDetectionState
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("RMPSTATE");
    private static readonly ConditionalWeakTable<BuildContext, RuntimeDetectionStateLayout> States = new();

    public static RuntimeDetectionStateLayout Ensure(BuildContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        return States.GetValue(ctx, Create);
    }

    public static void Enable(BuildContext ctx, RuntimeDetectionKind checks)
    {
        RuntimeDetectionStateLayout state = Ensure(ctx);
        ulong enabled = BinaryPrimitives.ReadUInt64LittleEndian(
            ctx.Pe.ReadRva(state.Rva + RuntimeDetectionStateLayout.EnabledChecksOffset, 8));
        enabled |= (ulong)checks;
        ctx.WriteData(
            state.Rva + RuntimeDetectionStateLayout.EnabledChecksOffset,
            BitConverter.GetBytes(enabled));
    }

    /// <summary>Emits an atomic, idempotent detection update. The caller supplies
    /// a register holding the runtime address of the state record. RCX is
    /// clobbered when session taint is enabled; it is volatile in the Windows
    /// x64 ABI.</summary>
    public static void EmitRecord(
        Asm asm,
        Reg statePointer,
        RuntimeDetectionKind kind,
        bool taintSession,
        ulong taintConstant,
        string labelPrefix)
    {
        ArgumentNullException.ThrowIfNull(asm);
        if (kind == RuntimeDetectionKind.None || !IsSingleBit((ulong)kind))
            throw new ArgumentOutOfRangeException(nameof(kind), "A single detection bit is required.");
        if (string.IsNullOrWhiteSpace(labelPrefix))
            throw new ArgumentException("A unique label prefix is required.", nameof(labelPrefix));

        string alreadyRecorded = $"{labelPrefix}_already_recorded";
        ulong bit = (ulong)kind;

        // LOCK BTS both publishes this producer's bit and elects exactly one
        // producer to apply its associated taint. Different bits can be raised
        // concurrently without either update being lost.
        asm.LockBtsMi(
            statePointer,
            RuntimeDetectionStateLayout.DetectionFlagsOffset,
            checked((byte)BitOperations.TrailingZeroCount(bit)));
        asm.Jcc(Cc.B, alreadyRecorded);

        if (taintSession)
        {
            asm.MovRi(Reg.Rcx, unchecked((long)taintConstant));
            asm.LockXorMr(
                statePointer,
                Reg.Rcx,
                RuntimeDetectionStateLayout.SessionKeyOffset);
        }

        asm.Label(alreadyRecorded);
    }

    private static RuntimeDetectionStateLayout Create(BuildContext ctx)
    {
        uint rva = ctx.AllocData(RuntimeDetectionStateLayout.RecordSize, 16);
        ulong sessionKey = (ulong)ctx.Rng.NextInt64() | 1UL;
        var record = new byte[RuntimeDetectionStateLayout.RecordSize];
        Magic.CopyTo(record, RuntimeDetectionStateLayout.MagicOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(
            record.AsSpan(RuntimeDetectionStateLayout.VersionOffset), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(
            record.AsSpan(RuntimeDetectionStateLayout.SizeOffset), RuntimeDetectionStateLayout.RecordSize);
        BinaryPrimitives.WriteUInt64LittleEndian(
            record.AsSpan(RuntimeDetectionStateLayout.SessionKeyOffset), sessionKey);
        ctx.WriteData(rva, record);
        ctx.Log.Add(new("runtime-state", $"shared detection state allocated at RVA {rva:X8}"));
        return new RuntimeDetectionStateLayout(rva, sessionKey);
    }

    private static bool IsSingleBit(ulong value) => (value & (value - 1)) == 0;
}
