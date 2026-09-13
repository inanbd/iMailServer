using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
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

        // Tunnelling handlers, so activity is recorded even when a child control handles the
        // event. Bubbling ones would miss a keystroke consumed by a text box - which is most of
        // them, and would make the idle timer fire while somebody was actively typing.
        PreviewMouseDown += OnUserActivity;
        PreviewKeyDown += OnUserActivity;
        PreviewMouseWheel += OnUserActivity;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e) =>
        await _shell.StartAsync().ConfigureAwait(true);

    private void OnUserActivity(object sender, InputEventArgs e) => _shell.RecordActivity();

    protected override void OnClosing(CancelEventArgs e)
    {
        // Disposes the idle timer and the current page, which for the dashboard means stopping
        // a background refresh loop that would otherwise keep polling after the window has gone.
        _shell.Dispose();

        base.OnClosing(e);
    }
}
