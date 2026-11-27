using System.Windows;

namespace Rampart.Gui;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // Keep release validation noninteractive: the packaged WinExe can prove
        // its version and runtime closure without opening a window on the build host.
        if (e.Args is ["--version"])
        {
            Version version = typeof(App).Assembly.GetName().Version ?? new Version(0, 0, 0);
            Console.WriteLine($"rampart-gui {version.Major}.{version.Minor}.{version.Build}");
            Shutdown(0);
            return;
        }

        base.OnStartup(e);
    }
}
