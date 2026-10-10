using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Rampart.Managed;

// Cecil's embedded providers expose their in-memory implementation through the
// filename overload only. The name is validated but never opened: all symbols
// are read from, or embedded into, the module's debug directory.
internal sealed class ManagedEmbeddedReader : ISymbolReaderProvider
{
    public ISymbolReader GetSymbolReader(ModuleDefinition module, string fileName)
        => new EmbeddedPortablePdbReaderProvider().GetSymbolReader(module, module.Name);
    public ISymbolReader GetSymbolReader(ModuleDefinition module, Stream symbolStream)
        => GetSymbolReader(module, module.Name);
}

internal sealed class ManagedEmbeddedWriter : ISymbolWriterProvider
{
    public ISymbolWriter GetSymbolWriter(ModuleDefinition module, string fileName)
        => new EmbeddedPortablePdbWriterProvider().GetSymbolWriter(module, module.Name);
    public ISymbolWriter GetSymbolWriter(ModuleDefinition module, Stream symbolStream)
        => GetSymbolWriter(module, module.Name);
}
