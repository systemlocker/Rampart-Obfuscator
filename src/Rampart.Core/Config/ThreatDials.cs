namespace Rampart.Config;

/// <summary>Threat-focus dials: pick attacker types and the dials raise the knobs
/// that answer them, one level over the preset, without touching anything else.</summary>
public static class ThreatDials
{
    /// <summary>Applies dial bumps to a settings object in place. Each focused
    /// threat raises every knob tagged for it by one level (capped at Maximum).
    /// Knobs already overridden by name are left alone — explicit user intent wins.</summary>
    public static void Apply(ProtectionSettings settings, KnobCatalog catalog)
    {
        foreach (var tag in settings.ThreatFocus)
        {
            if (!ThreatTags.All.Contains(tag))
                throw new ArgumentException($"Unknown threat tag '{tag}'. Valid: {string.Join(", ", ThreatTags.All)}");
        }

        foreach (var knob in catalog.All)
        {
            if (settings.Knobs.ContainsKey(knob.Id))
                continue; // explicit override wins over dials

            var relevant = settings.ThreatFocus.Any(knob.HasTag);
            if (!relevant)
                continue;

            var current = settings.LevelOf(knob);
            if (current == ProtectionLevel.Off)
                continue; // dials intensify, they do not opt in deliberate-use knobs

            var bumped = ProtectionCapabilities.ClampToReady(
                knob.Id,
                (ProtectionLevel)Math.Min((int)current + 1, (int)ProtectionLevel.Maximum));
            if (bumped != current)
                settings.Knobs[knob.Id] = bumped;
        }
    }
}
