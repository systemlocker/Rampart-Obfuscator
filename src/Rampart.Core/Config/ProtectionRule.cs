namespace Rampart.Config;

/// <summary>The metadata field a function-region rule matches.</summary>
public enum ProtectionRuleScope
{
    Any,
    Symbol,
    Namespace,
    Module,
    Section,
    Source,
    Rva,
}

/// <summary>
/// An ordered per-function override. Rules are evaluated in document order and
/// the last matching rule wins for each knob. A preset of "off" disables every
/// function-scoped transform in the matched region.
/// </summary>
public sealed class ProtectionRule
{
    public string Match { get; set; } = "*";
    public ProtectionRuleScope Scope { get; set; } = ProtectionRuleScope.Any;
    public string? Preset { get; set; }
    public uint? StartRva { get; set; }
    public uint? EndRva { get; set; }
    public Dictionary<string, ProtectionLevel> Knobs { get; init; } = new(StringComparer.Ordinal);
}

/// <summary>An inclusive-start, exclusive-end function selection range.</summary>
public sealed class RvaRange
{
    public uint Start { get; set; }
    public uint End { get; set; }
}
