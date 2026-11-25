using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

// Cecil's embedded providers expose their in-memory implementation through the
// filename overload only. The name is validated but never opened: all symbols
// are read from, or embedded into, the module's debug directory.
internal sealed class ManagedEmbeddedReader : ISymbolReaderProvider
{
    private static string SafeModuleName(ModuleDefinition module) =>
        string.IsNullOrWhiteSpace(module.Name) ? "module.dll" : module.Name;
    public ISymbolReader GetSymbolReader(ModuleDefinition module, string fileName)
        => new EmbeddedPortablePdbReaderProvider().GetSymbolReader(module, SafeModuleName(module));
    public ISymbolReader GetSymbolReader(ModuleDefinition module, Stream symbolStream)
        => GetSymbolReader(module, SafeModuleName(module));
}

internal sealed class ManagedEmbeddedWriter : ISymbolWriterProvider
{
    private static string SafeModuleName(ModuleDefinition module) =>
        string.IsNullOrWhiteSpace(module.Name) ? "module.dll" : module.Name;
    public ISymbolWriter GetSymbolWriter(ModuleDefinition module, string fileName)
        => new EmbeddedPortablePdbWriterProvider().GetSymbolWriter(module, SafeModuleName(module));
    public ISymbolWriter GetSymbolWriter(ModuleDefinition module, Stream symbolStream)
        => GetSymbolWriter(module, SafeModuleName(module));
}
