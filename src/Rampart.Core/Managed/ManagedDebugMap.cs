using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

internal sealed class ManagedDebugMap
{
    private sealed record Point(Instruction? Instruction, Document Document, int Offset, string OriginalDocument,
        int StartLine, int StartColumn, int EndLine, int EndColumn);
    private readonly int originalToken;
    private readonly Point[] points;
    internal ManagedDebugMap(MethodDefinition method)
    {
        originalToken = method.MetadataToken.ToInt32();
        var instructions = method.HasBody ? method.Body.Instructions.ToDictionary(instruction => instruction.Offset) : [];
        points = method.DebugInformation.SequencePoints.Select(point => new Point(instructions.GetValueOrDefault(point.Offset), point.Document,
            point.Offset, point.Document.Url, point.StartLine, point.StartColumn, point.EndLine, point.EndColumn)).ToArray();
    }

    internal void Rebind(MethodDefinition method)
    {
        // Bind source coordinates to retained instruction objects before the writer
        // computes new offsets. Numeric source offsets are invalid after insertion.
        method.DebugInformation.SequencePoints.Clear();
        if (!method.HasBody) return;
        var instructions = method.Body.Instructions.ToHashSet();
        var retained = points.Where(point => point.Instruction is not null && instructions.Contains(point.Instruction))
            .ToLookup(point => point.Instruction!);
        foreach (var instruction in method.Body.Instructions)
            foreach (var point in retained[instruction])
                method.DebugInformation.SequencePoints.Add(new SequencePoint(instruction, point.Document)
                { StartLine = point.StartLine, StartColumn = point.StartColumn, EndLine = point.EndLine, EndColumn = point.EndColumn });
    }

    internal IReadOnlyList<ManagedSequencePointMapping> Identity() => points.Select(point => new ManagedSequencePointMapping(
        originalToken, originalToken, point.Offset, point.Offset, point.OriginalDocument, point.OriginalDocument,
        point.StartLine, point.StartColumn, point.EndLine, point.EndColumn, "preserved")).ToArray();

    internal IReadOnlyList<ManagedSequencePointMapping> Emitted(MethodDefinition method, MethodDefinition emitted, bool symbolsWritten, string? owner)
    {
        var instructions = method.HasBody ? method.Body.Instructions.ToHashSet() : [];
        return points.Select(point =>
        {
            int? offset = symbolsWritten && point.Instruction is not null && instructions.Contains(point.Instruction) ? point.Instruction.Offset : null;
            string? document = offset is not null ? point.Document.Url : null;
            if (offset is not null && !emitted.DebugInformation.SequencePoints.Any(actual => actual.Offset == offset && actual.Document.Url == document
                && actual.StartLine == point.StartLine && actual.StartColumn == point.StartColumn && actual.EndLine == point.EndLine && actual.EndColumn == point.EndColumn))
                ManagedPreflight.Fail("MANAGED_SYMBOL_MAP_INVALID", "An emitted sequence point differs from its recorded source mapping.");
            string status = !symbolsWritten ? "symbols-omitted" : offset is not null ? "mapped"
                : owner == "managed-vm" ? "removed-by-virtualization" : "unmapped-source-offset";
            return new ManagedSequencePointMapping(originalToken, emitted.MetadataToken.ToInt32(), point.Offset, offset,
                point.OriginalDocument, document, point.StartLine, point.StartColumn, point.EndLine, point.EndColumn, status);
        }).ToArray();
    }
}
