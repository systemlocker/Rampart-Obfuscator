using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;

namespace Rampart.Managed;

internal static class ManagedInstructionBounds
{
    private static readonly Dictionary<ushort, OperandType> Operands = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.FieldType == typeof(OpCode)).Select(f => (OpCode)f.GetValue(null)!)
        .ToDictionary(op => unchecked((ushort)op.Value), op => op.OperandType);

    internal static void Validate(byte[] bytes)
    {
        var offset = 0; var starts = new HashSet<int>(); var targets = new List<long>();
        while (offset < bytes.Length)
        {
            starts.Add(offset);
            ushort code = bytes[offset++];
            if (code == 0xfe) { if (offset == bytes.Length) Fail(); code = (ushort)(0xfe00 | bytes[offset++]); }
            if (!Operands.TryGetValue(code, out var operand)) Fail();
            var size = operand switch
            {
                OperandType.InlineNone => 0,
                OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineBrTarget or OperandType.InlineField or OperandType.InlineI or OperandType.InlineMethod
                    or OperandType.InlineSig or OperandType.InlineString or OperandType.InlineTok or OperandType.InlineType or OperandType.ShortInlineR => 4,
                OperandType.InlineI8 or OperandType.InlineR => 8,
                OperandType.InlineSwitch => 4,
                _ => -1
            };
            if (size < 0 || offset > bytes.Length - size) Fail();
            if (operand == OperandType.InlineSwitch)
            {
                var count = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset)); offset += 4;
                if (count < 0 || count > (bytes.Length - offset) / 4) Fail();
                var end = offset + count * 4;
                for (var i = 0; i < count; i++) targets.Add((long)end + BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset + i * 4)));
                offset = end; continue;
            }
            if (operand == OperandType.InlineBrTarget) targets.Add((long)offset + size + BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset)));
            else if (operand == OperandType.ShortInlineBrTarget) targets.Add((long)offset + size + (sbyte)bytes[offset]);
            offset += size;
        }
        foreach (var target in targets) if (target < 0 || target >= bytes.Length || !starts.Contains((int)target)) Fail();
    }
    private static void Fail() => ManagedPreflight.Fail("MANAGED_INVALID_IL", "A method contains an invalid or unbounded IL operand.");
}
