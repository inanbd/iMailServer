using System.ComponentModel;
using System.Windows;
using MailServer.Admin.ViewModels;

namespace MailServer.Admin.Views;

/// <summary>The shell window.</summary>
public partial class MainWindow : Window
{
    private readonly ShellViewModel _shell;

    public MainWindow(ShellViewModel shell)
    {
        ArgumentNullException.ThrowIfNull(shell);

        _shell = shell;
        DataContext = shell;

        InitializeComponent();

        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e) => _shell.Start();

    protected override void OnClosing(CancelEventArgs e)
    {
        // The dashboard holds a background refresh loop. Cancelling it here stops a
        // pointless IPC round trip every few seconds after the window has gone.
        if (_shell.CurrentPage is IDisposable disposable)
        {
            disposable.Dispose();
        }

        base.OnClosing(e);
    }
}
