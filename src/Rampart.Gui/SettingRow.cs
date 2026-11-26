using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Rampart.Config;
using Rampart.Targets;

namespace Rampart.Gui;

internal sealed class SettingRow : INotifyPropertyChanged
{
    private const string InheritPreset = "Preset";
    private string _selectedLevel = InheritPreset;
    private bool _isAvailable;
    private string _availability = "";

    public SettingRow(KnobDef definition)
    {
        Definition = definition;
        LevelChoices = [];
        ApplyTarget(ProtectionTargetKind.NativePe);
    }

    public KnobDef Definition { get; }
    public string Id => Definition.Id;
    public string Group => KnobGroups.Title(Definition.Group);
    public string Name => Definition.Name;
    public string Summary => Definition.Summary;
    public ObservableCollection<string> LevelChoices { get; }

    public string SelectedLevel
    {
        get => _selectedLevel;
        set
        {
            if (_selectedLevel == value) return;
            _selectedLevel = value;
            OnPropertyChanged();
        }
    }

    public bool IsAvailable
    {
        get => _isAvailable;
        private set
        {
            if (_isAvailable == value) return;
            _isAvailable = value;
            OnPropertyChanged();
        }
    }

    public string Availability
    {
        get => _availability;
        private set
        {
            if (_availability == value) return;
            _availability = value;
            OnPropertyChanged();
        }
    }

    public ProtectionLevel? ExplicitLevel => SelectedLevel == InheritPreset
        ? null
        : Enum.Parse<ProtectionLevel>(SelectedLevel, ignoreCase: true);

    public bool ApplyTarget(ProtectionTargetKind target)
    {
        ProtectionLevel maximum = TargetCapabilities.MaximumLevel(Id, target);
        string previous = SelectedLevel;
        LevelChoices.Clear();
        LevelChoices.Add(InheritPreset);
        LevelChoices.Add(ProtectionLevel.Off.DisplayName());
        for (var level = ProtectionLevel.Light; level <= maximum; level++)
            LevelChoices.Add(level.DisplayName());

        IsAvailable = maximum != ProtectionLevel.Off;
        Availability = IsAvailable ? $"Through {maximum.DisplayName()}" : "Unavailable for target";
        SelectedLevel = LevelChoices.Contains(previous) ? previous : InheritPreset;
        return previous != InheritPreset && previous != SelectedLevel;
    }

    public bool Matches(string query) => string.IsNullOrWhiteSpace(query)
        || Id.Contains(query, StringComparison.OrdinalIgnoreCase)
        || Name.Contains(query, StringComparison.OrdinalIgnoreCase)
        || Group.Contains(query, StringComparison.OrdinalIgnoreCase)
        || Summary.Contains(query, StringComparison.OrdinalIgnoreCase);

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
