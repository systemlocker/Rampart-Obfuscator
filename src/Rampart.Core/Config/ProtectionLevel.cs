namespace Rampart.Config;

/// <summary>Intensity of an individual protection knob. Levels mirror the public
/// Atlas dial names so configurations transfer by intent, not by brand.</summary>
public enum ProtectionLevel
{
    Off = 0,
    Light = 1,
    Balanced = 2,
    Heavy = 3,
    Maximum = 4,
}

public static class ProtectionLevelExtensions
{
    public static string DisplayName(this ProtectionLevel level) => level switch
    {
        ProtectionLevel.Off => "Off",
        ProtectionLevel.Light => "Light",
        ProtectionLevel.Balanced => "Balanced",
        ProtectionLevel.Heavy => "Heavy",
        ProtectionLevel.Maximum => "Maximum",
        _ => level.ToString(),
    };
}
