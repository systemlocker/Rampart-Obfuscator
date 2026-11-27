using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;
using Rampart.Config;
using Rampart.Targets;

namespace Rampart.Gui;

public partial class MainWindow : Window
{
    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaUseImmersiveDarkModeBefore20H1 = 19;
    private const int DwmwaBorderColor = 34;
    private const int DwmwaCaptionColor = 35;
    private const int DwmwaTextColor = 36;

    // COLORREF values (0x00BBGGRR) matching SurfaceColor (#081009), TextColor (#DEDAD6), and DividerColor (#253526).
    private const int TitleBarCaptionColorRef = 0x00091008;
    private const int TitleBarTextColorRef = 0x00D6DADE;
    private const int TitleBarBorderColorRef = 0x00263525;

    private readonly ObservableCollection<SettingRow> _settings;
    private readonly ICollectionView _settingsView;
    private ProtectionTargetKind _targetKind = ProtectionTargetKind.NativePe;
    private ProtectionSettings? _loadedSettings;
    private string? _inputPath;
    private string? _unsupportedReason;
    private bool _inputRejected;
    private bool _inspectingInput;
    private CancellationTokenSource? _runCancellation;
    private bool _canProtect;
    private int _inputGeneration;

    public MainWindow()
    {
        InitializeComponent();
        PresetCombo.ItemsSource = Presets.All;
        PresetCombo.SelectedItem = Presets.Balanced;

        _settings = new(KnobCatalog.Load().All
            .Where(knob => ProtectionCapabilities.IsReady(knob.Id))
            .Select(knob => new SettingRow(knob)));
        _settingsView = CollectionViewSource.GetDefaultView(_settings);
        _settingsView.Filter = item => item is SettingRow row && row.Matches(SettingsSearchTextBox.Text);
        SettingsGrid.ItemsSource = _settingsView;
        SettingsGrid.SelectionChanged += SettingsGrid_SelectionChanged;
        UpdateSettingsCount();

        WorkerPathTextBox.Text = CliWorker.FindDefaultWorker() ?? string.Empty;
        UpdateWorkerState();
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        ApplyDarkTitleBar();
    }

    private void ApplyDarkTitleBar()
    {
        IntPtr hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == IntPtr.Zero) return;

        // Opt the non-client frame into dark mode and match the header surface on Windows 11.
        // Older Windows builds ignore unsupported DWM attributes harmlessly.
        int dark = 1;
        if (DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref dark, sizeof(int)) != 0)
            _ = DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkModeBefore20H1, ref dark, sizeof(int));

        int caption = TitleBarCaptionColorRef;
        int text = TitleBarTextColorRef;
        int border = TitleBarBorderColorRef;
        _ = DwmSetWindowAttribute(hwnd, DwmwaCaptionColor, ref caption, sizeof(int));
        _ = DwmSetWindowAttribute(hwnd, DwmwaTextColor, ref text, sizeof(int));
        _ = DwmSetWindowAttribute(hwnd, DwmwaBorderColor, ref border, sizeof(int));
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    private async void SetInput(string path)
    {
        if (_runCancellation is not null) return;
        int generation = ++_inputGeneration;
        try
        {
            path = Path.GetFullPath(path);
            if (!File.Exists(path)) throw new FileNotFoundException("Input file was not found.", path);
            _inputPath = path;
            _canProtect = false;
            _inputRejected = false;
            _unsupportedReason = null;
            _inspectingInput = true;
            InputNameText.Text = path;
            InputNameText.ToolTip = path;
            OutputPathTextBox.Text = DefaultOutputPath(path);
            TargetText.Text = "Inspecting...";
            TargetStatusText.Visibility = Visibility.Collapsed;
            TargetDetailText.Text = "Reading target metadata.";
            SetRunState("Inspecting input...", "MutedBrush");
            UpdateWorkerState();

            TargetClassification classification = await Task.Run(() =>
            {
                byte[] input = ProtectionPipeline.ReadInput(path);
                return TargetClassifier.Classify(input, path);
            });
            if (generation != _inputGeneration) return;

            _inspectingInput = false;
            _targetKind = classification.Target.Kind;
            _canProtect = classification.CanProtect;
            TargetText.Text = FormatTarget(classification.Target);
            if (classification.CanProtect)
            {
                TargetStatusText.Text = "Supported";
                TargetStatusText.Foreground = FindBrush("AccentBrush");
                TargetStatusText.Visibility = Visibility.Visible;
                TargetDetailText.Text = $"{classification.Target.Architecture} · {classification.Target.DeploymentShape}";
                SetRunState("Ready to protect", "MutedBrush");
            }
            else
            {
                string guidance = FormatUnsupportedGuidance(classification.Target, classification.ReasonCode);
                _unsupportedReason = guidance;
                TargetStatusText.Text = "Unsupported — cannot protect";
                TargetStatusText.Foreground = FindBrush("WarningBrush");
                TargetStatusText.Visibility = Visibility.Visible;
                TargetDetailText.Text = $"{classification.Target.Architecture} · {classification.Disposition} ({classification.ReasonCode})\n{guidance}";
                SetRunState("Target unsupported — cannot protect", "WarningBrush");
            }
            ApplyTarget(classification.Target.Kind);
            UpdateWorkerState();
        }
        catch (Exception ex)
        {
            if (generation != _inputGeneration) return;
            _inspectingInput = false;
            _inputPath = null;
            _canProtect = false;
            _inputRejected = true;
            _unsupportedReason = ex.Message;
            TargetText.Text = "Input rejected";
            TargetStatusText.Text = "Could not inspect file";
            TargetStatusText.Foreground = FindBrush("DangerBrush");
            TargetStatusText.Visibility = Visibility.Visible;
            TargetDetailText.Text = ex.Message;
            LogTextBox.Text = ex.Message;
            SetRunState("Input rejected", "DangerBrush");
            UpdateWorkerState();
        }
    }

    private void ApplyTarget(ProtectionTargetKind target)
    {
        int cleared = _settings.Count(row => row.ApplyTarget(target));
        bool nativePreset = target is ProtectionTargetKind.NativePe or ProtectionTargetKind.NativePeX86;
        PresetCombo.IsEnabled = nativePreset;
        PresetHintText.Text = nativePreset
            ? "Explicit setting overrides take precedence."
            : "Managed and NativeAOT targets use explicit setting selections.";
        _settingsView.Refresh();
        UpdateSettingsCount();
        if (cleared != 0)
            LogTextBox.Text = $"{cleared} explicit setting override(s) were cleared because their levels are unavailable for {FormatKind(target)}.";
    }

    private ProtectionSettings BuildSettings()
    {
        ProtectionSettings settings = _loadedSettings is null
            ? new ProtectionSettings()
            : ProtectionSettingsJson.Deserialize(ProtectionSettingsJson.Serialize(_loadedSettings));

        settings.Preset = _targetKind switch
        {
            ProtectionTargetKind.NativePe or ProtectionTargetKind.NativePeX86 => PresetCombo.SelectedItem as string ?? Presets.Balanced,
            ProtectionTargetKind.NativeAot => "off",
            _ => Presets.Balanced,
        };
        settings.Seed = settings.Seed == 0 ? Random.Shared.NextInt64() : settings.Seed;
        settings.Targets ??= new TargetProtectionOptions();
        settings.Targets.Override = _targetKind;
        settings.Knobs.Clear();
        foreach (SettingRow row in _settings)
        {
            if (!row.IsAvailable || row.ExplicitLevel is not { } level) continue;
            settings.Knobs[row.Id] = level;
        }
        return settings;
    }

    private void BrowseInput_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose an application to protect",
            Filter = "Windows applications (*.exe;*.dll)|*.exe;*.dll|All files (*.*)|*.*",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) == true) SetInput(dialog.FileName);
    }

    private void BrowseOutput_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Choose protected output",
            Filter = "Windows applications (*.exe;*.dll)|*.exe;*.dll|All files (*.*)|*.*",
            FileName = string.IsNullOrWhiteSpace(OutputPathTextBox.Text) ? null : Path.GetFileName(OutputPathTextBox.Text),
            InitialDirectory = string.IsNullOrWhiteSpace(OutputPathTextBox.Text) ? null : Path.GetDirectoryName(OutputPathTextBox.Text),
            OverwritePrompt = false,
        };
        if (dialog.ShowDialog(this) == true) OutputPathTextBox.Text = dialog.FileName;
    }

    private void BrowseWorker_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Locate the Rampart CLI worker",
            Filter = "Rampart CLI (rampart.exe;rampart.dll)|rampart.exe;rampart.dll",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) == true) WorkerPathTextBox.Text = dialog.FileName;
    }

    private void LoadConfig_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Load Rampart configuration", Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            _loadedSettings = ProtectionSettingsJson.Deserialize(File.ReadAllText(dialog.FileName));
            if (Presets.All.Contains(_loadedSettings.Preset, StringComparer.OrdinalIgnoreCase))
                PresetCombo.SelectedItem = Presets.All.First(p => p.Equals(_loadedSettings.Preset, StringComparison.OrdinalIgnoreCase));
            int skipped = 0;
            foreach (SettingRow row in _settings)
            {
                row.SelectedLevel = "Preset";
                if (_loadedSettings.Knobs.TryGetValue(row.Id, out ProtectionLevel level))
                {
                    string name = level.DisplayName();
                    if (row.LevelChoices.Contains(name)) row.SelectedLevel = name;
                    else skipped++;
                }
            }
            LogTextBox.Text = skipped == 0
                ? $"Loaded configuration: {dialog.FileName}"
                : $"Loaded configuration with {skipped} override(s) omitted because their levels are unavailable for the current target.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Configuration could not be loaded", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SaveConfig_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Save Rampart configuration",
            Filter = "JSON files (*.json)|*.json",
            FileName = "rampart.config.json",
            OverwritePrompt = true,
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            File.WriteAllText(dialog.FileName, ProtectionSettingsJson.Serialize(BuildSettings()));
            LogTextBox.Text = $"Saved configuration: {dialog.FileName}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Configuration could not be saved", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void Protect_Click(object sender, RoutedEventArgs e)
    {
        if (_inputPath is null || !File.Exists(_inputPath))
        {
            MessageBox.Show(this, "Choose an input application first.", "Input required", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        string output = OutputPathTextBox.Text.Trim();
        string worker = WorkerPathTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(output))
        {
            MessageBox.Show(this, "Choose an output location.", "Output required", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        string temporaryConfig = Path.Combine(Path.GetTempPath(), $"rampart-gui-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(temporaryConfig, ProtectionSettingsJson.Serialize(BuildSettings()));
            SetBusy(true);
            LogTextBox.Text = "Starting isolated Rampart CLI worker...";
            _runCancellation = new CancellationTokenSource();
            CliRunResult result = await CliWorker.ProtectAsync(worker, _inputPath, Path.GetFullPath(output), temporaryConfig,
                OverwriteCheckBox.IsChecked == true, _runCancellation.Token);
            LogTextBox.Text = CombineOutput(result.StandardOutput, result.StandardError);
            if (result.ExitCode == 0)
            {
                SetRunState("Protection completed", "AccentBrush");
                MessageBox.Show(this, $"Protected output written to:\n{Path.GetFullPath(output)}", "Rampart completed",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                SetRunState($"Worker exited with code {result.ExitCode}", "DangerBrush");
                MessageBox.Show(this, string.IsNullOrWhiteSpace(result.StandardError) ? result.StandardOutput : result.StandardError,
                    "Rampart did not write output", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (OperationCanceledException)
        {
            LogTextBox.Text = "Protection cancelled. The worker process was stopped.";
            SetRunState("Cancelled", "WarningBrush");
        }
        catch (Exception ex)
        {
            LogTextBox.Text = ex.Message;
            SetRunState("Could not run protection", "DangerBrush");
            MessageBox.Show(this, ex.Message, "Rampart", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _runCancellation?.Dispose();
            _runCancellation = null;
            SetBusy(false);
            try { File.Delete(temporaryConfig); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => _runCancellation?.Cancel();

    protected override void OnClosed(EventArgs e)
    {
        // Closing the front end must not leave an unseen protection worker
        // running against files the user can no longer see or cancel.
        _runCancellation?.Cancel();
        base.OnClosed(e);
    }

    private void SetBusy(bool busy)
    {
        ProtectButton.IsEnabled = false;
        CancelButton.IsEnabled = busy;
        CancelButton.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        WorkerProgress.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        PresetCombo.IsEnabled = !busy && _targetKind is ProtectionTargetKind.NativePe or ProtectionTargetKind.NativePeX86;
        SettingsGrid.IsEnabled = !busy;
        OutputPathTextBox.IsEnabled = !busy;
        if (busy)
        {
            ActionHintText.Visibility = Visibility.Collapsed;
            ProtectButton.ToolTip = "Protection is currently running.";
            SetRunState("Running protection worker...", "MutedBrush");
        }
        else
        {
            UpdateWorkerState();
        }
    }

    private void Input_DragEnter(object sender, DragEventArgs e)
    {
        bool file = e.Data.GetDataPresent(DataFormats.FileDrop);
        e.Effects = file ? DragDropEffects.Copy : DragDropEffects.None;
        DropBorder.BorderBrush = file ? FindBrush("AccentBrush") : FindBrush("BorderBrush");
        DropBorder.Background = file ? FindBrush("TintBrush") : FindBrush("CanvasBrush");
        e.Handled = true;
    }

    private void Input_DragLeave(object sender, DragEventArgs e)
    {
        DropBorder.BorderBrush = FindBrush("BorderBrush");
        DropBorder.Background = FindBrush("CanvasBrush");
    }

    private void Input_Drop(object sender, DragEventArgs e)
    {
        DropBorder.BorderBrush = FindBrush("BorderBrush");
        DropBorder.Background = FindBrush("CanvasBrush");
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files) SetInput(files[0]);
    }

    private void SettingsSearch_TextChanged(object sender, TextChangedEventArgs e)
    {
        _settingsView?.Refresh();
        UpdateSettingsCount();
    }

    private void SettingsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        SettingDescriptionText.Text = SettingsGrid.SelectedItem is SettingRow row
            ? $"{row.Summary}  {row.Availability}."
            : "Select a setting to view its description.";
    }

    private void WorkerPath_TextChanged(object sender, TextChangedEventArgs e) => UpdateWorkerState();

    private void PresetCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsLoaded && PresetCombo.SelectedItem is string preset && (_canProtect || _inputPath is null))
            SetRunState($"{char.ToUpperInvariant(preset[0])}{preset[1..]} preset selected", "MutedBrush");
    }

    private void UpdateSettingsCount()
    {
        int total = _settings.Count;
        int visible = _settingsView.Cast<object>().Count();
        SettingsCountText.Text = visible == total
            ? $"{total} settings"
            : $"{visible} of {total} settings";
    }

    private void UpdateWorkerState()
    {
        string path = WorkerPathTextBox.Text.Trim();
        WorkerPathTextBox.ToolTip = string.IsNullOrWhiteSpace(path) ? null : path;
        bool valid = File.Exists(path) && (Path.GetFileName(path).Equals("rampart.exe", StringComparison.OrdinalIgnoreCase)
            || Path.GetFileName(path).Equals("rampart.dll", StringComparison.OrdinalIgnoreCase));
        WorkerStateText.Text = valid ? "CLI worker ready" : "CLI worker not found";
        WorkerStateDot.Fill = FindBrush(valid ? "AccentBrush" : "WarningBrush");

        bool running = _runCancellation is not null;
        bool canRun = !running && !_inspectingInput && _canProtect && valid;
        ProtectButton.IsEnabled = canRun;

        // Explain disabled states inline beside the Protect button as well as on hover.
        if (running)
        {
            ActionHintText.Visibility = Visibility.Collapsed;
            ProtectButton.ToolTip = "Protection is currently running.";
        }
        else if (_inspectingInput)
        {
            ActionHintText.Text = "Inspecting...";
            ActionHintText.Foreground = FindBrush("MutedBrush");
            ActionHintText.Visibility = Visibility.Visible;
            ProtectButton.ToolTip = "Waiting for target inspection to finish.";
        }
        else if (_inputRejected)
        {
            ActionHintText.Text = "Input rejected";
            ActionHintText.Foreground = FindBrush("DangerBrush");
            ActionHintText.Visibility = Visibility.Visible;
            ProtectButton.ToolTip = _unsupportedReason ?? "The selected input could not be inspected.";
        }
        else if (_inputPath is null)
        {
            ActionHintText.Text = valid ? "Choose a file" : "CLI worker missing";
            ActionHintText.Foreground = FindBrush(valid ? "MutedBrush" : "WarningBrush");
            ActionHintText.Visibility = Visibility.Visible;
            ProtectButton.ToolTip = valid
                ? "Choose an EXE or DLL input file first."
                : "Locate rampart.exe or rampart.dll, then choose an input file.";
        }
        else if (!_canProtect)
        {
            ActionHintText.Text = "Target unsupported";
            ActionHintText.Foreground = FindBrush("WarningBrush");
            ActionHintText.Visibility = Visibility.Visible;
            ProtectButton.ToolTip = _unsupportedReason ?? "This target is unsupported and cannot be protected.";
        }
        else if (!valid)
        {
            ActionHintText.Text = "CLI worker missing";
            ActionHintText.Foreground = FindBrush("WarningBrush");
            ActionHintText.Visibility = Visibility.Visible;
            ProtectButton.ToolTip = "Locate rampart.exe or rampart.dll in the CLI worker section.";
        }
        else
        {
            ActionHintText.Visibility = Visibility.Collapsed;
            ProtectButton.ToolTip = "Protect the selected file using the current settings.";
        }
    }

    private void SetRunState(string message, string brushKey)
    {
        RunStateText.Text = message;
        RunStateText.Foreground = FindBrush(brushKey);
    }

    private Brush FindBrush(string key) => (Brush)FindResource(key);

    private static string DefaultOutputPath(string inputPath)
    {
        string directory = Path.GetDirectoryName(inputPath)!;
        string extension = Path.GetExtension(inputPath);
        return Path.Combine(directory, $"{Path.GetFileNameWithoutExtension(inputPath)}.protected{extension}");
    }

    private static string FormatTarget(ProtectionTarget target)
    {
        string architecture = string.IsNullOrWhiteSpace(target.Architecture) || target.Architecture == "unknown"
            ? ""
            : " " + target.Architecture;
        return target.Kind switch
        {
            ProtectionTargetKind.NativePe => $"Native Windows{architecture} executable",
            ProtectionTargetKind.NativePeX86 => "Native Windows x86 executable",
            ProtectionTargetKind.NativeAot => $"Windows{architecture} NativeAOT executable",
            ProtectionTargetKind.ManagedIl when target.DeploymentShape == "managed-library" => "Managed .NET library",
            ProtectionTargetKind.ManagedIl when target.DeploymentShape == "managed-executable" => "Managed .NET executable",
            ProtectionTargetKind.ManagedIl => "Managed .NET assembly",
            ProtectionTargetKind.ReadyToRun => ".NET ReadyToRun assembly",
            ProtectionTargetKind.FrameworkDependentAppHost => ".NET framework-dependent apphost",
            ProtectionTargetKind.SelfContainedAppHost => ".NET self-contained apphost",
            ProtectionTargetKind.SingleFileBundle => ".NET single-file bundle",
            ProtectionTargetKind.MixedMode => ".NET mixed-mode assembly",
            ProtectionTargetKind.AlreadyProtected => "Already-protected Rampart artifact",
            ProtectionTargetKind.Unknown => "Unrecognized file",
            _ => target.Kind.ToString(),
        };
    }

    private static string FormatKind(ProtectionTargetKind kind) => kind switch
    {
        ProtectionTargetKind.NativePe => "the native Windows target",
        ProtectionTargetKind.NativePeX86 => "the native Windows x86 target",
        ProtectionTargetKind.NativeAot => "the Windows NativeAOT target",
        ProtectionTargetKind.ManagedIl => "the managed .NET target",
        ProtectionTargetKind.ReadyToRun => "ReadyToRun assembly",
        ProtectionTargetKind.FrameworkDependentAppHost => "Framework-dependent apphost",
        ProtectionTargetKind.SelfContainedAppHost => "Self-contained apphost",
        ProtectionTargetKind.SingleFileBundle => "Single-file bundle",
        ProtectionTargetKind.MixedMode => "Mixed-mode assembly",
        ProtectionTargetKind.AlreadyProtected => "Already protected",
        ProtectionTargetKind.Unknown => "Unknown file",
        _ => kind.ToString(),
    };

    private static string FormatUnsupportedGuidance(ProtectionTarget target, string reasonCode) => target.Kind switch
    {
        ProtectionTargetKind.NativePe when reasonCode == "target.native-platform" =>
            $"Rampart currently protects PE32+ x64 native executables; this file is {target.Architecture}.",
        ProtectionTargetKind.NativeAot when reasonCode == "target.nativeaot-platform" =>
            $"Rampart currently protects eligible Windows x64 NativeAOT executables; this file is {target.Architecture}.",
        ProtectionTargetKind.FrameworkDependentAppHost or ProtectionTargetKind.SelfContainedAppHost =>
            "Protect the managed application .dll before publishing this apphost.",
        ProtectionTargetKind.SingleFileBundle =>
            "Protect the managed .dll before single-file bundling.",
        ProtectionTargetKind.ReadyToRun =>
            "Protect the pure IL .dll before ReadyToRun compilation.",
        ProtectionTargetKind.MixedMode =>
            "Mixed-mode C++/CLI assemblies cannot be protected.",
        ProtectionTargetKind.AlreadyProtected =>
            "This file was already protected by Rampart. Protect the original build artifact instead.",
        _ => $"This target cannot be protected ({reasonCode}).",
    };

    private static string CombineOutput(string stdout, string stderr)
    {
        if (string.IsNullOrWhiteSpace(stderr)) return stdout.Trim();
        if (string.IsNullOrWhiteSpace(stdout)) return stderr.Trim();
        return $"{stdout.Trim()}\n\n{stderr.Trim()}";
    }
}
