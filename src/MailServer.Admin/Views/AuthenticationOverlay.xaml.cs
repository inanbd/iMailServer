using System.Windows.Controls;
using System.Windows.Input;
using MailServer.Admin.ViewModels;

namespace MailServer.Admin.Views;

/// <summary>
/// Code-behind for the authentication overlay.
/// </summary>
/// <remarks>
/// <para>
/// <b>The one place in this application with real code-behind, and for a specific reason.</b>
/// WPF's <see cref="PasswordBox"/> does not expose <c>Password</c> as a bindable dependency
/// property, deliberately: a bound string would live in the binding engine and on the managed
/// heap for as long as the view did, and could be observed by anything walking the visual tree.
/// </para>
/// <para>
/// So the password is read here, at the moment it is needed, passed straight to the view model
/// as a method argument, and the box is cleared immediately afterwards. The view model never
/// stores it. The alternative — a bindable <c>PasswordBox</c> helper, of which many exist — is
/// exactly the thing that property was designed to prevent.
/// </para>
/// </remarks>
public partial class AuthenticationOverlay : UserControl
{
    public AuthenticationOverlay() => InitializeComponent();

    private AuthenticationViewModel? ViewModel => DataContext as AuthenticationViewModel;

    private async void OnCompleteSetup(object sender, System.Windows.RoutedEventArgs e)
    {
        if (ViewModel is not { } viewModel)
        {
            return;
        }

        await viewModel
            .CompleteSetupAsync(SetupPassword.Password, SetupConfirmPassword.Password)
            .ConfigureAwait(true);

        ClearPasswordBoxes();
    }

    private async void OnSignIn(object sender, System.Windows.RoutedEventArgs e) =>
        await SignInAsync().ConfigureAwait(true);

    private async void OnSignInKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            await SignInAsync().ConfigureAwait(true);
        }
    }

    private async Task SignInAsync()
    {
        if (ViewModel is not { } viewModel)
        {
            return;
        }

        await viewModel.SignInAsync(SignInPassword.Password).ConfigureAwait(true);

        // Cleared whether or not it succeeded: on failure the administrator retypes, and the
        // wrong value should not linger on screen or in memory.
        SignInPassword.Clear();
    }

    private async void OnResetWithRecoveryKey(object sender, System.Windows.RoutedEventArgs e)
    {
        if (ViewModel is not { } viewModel)
        {
            return;
        }

        await viewModel
            .ResetWithRecoveryKeyAsync(
                RecoveryKeyEntry.Text,
                RecoveryNewPassword.Password,
                RecoveryConfirmPassword.Password)
            .ConfigureAwait(true);

        RecoveryKeyEntry.Clear();
        ClearPasswordBoxes();
    }

    private async void OnCompleteRequiredChange(object sender, System.Windows.RoutedEventArgs e)
    {
        if (ViewModel is not { } viewModel)
        {
            return;
        }

        await viewModel
            .CompleteRequiredChangeAsync(
                RequiredCurrentPassword.Password,
                RequiredNewPassword.Password,
                RequiredConfirmPassword.Password)
            .ConfigureAwait(true);

        ClearPasswordBoxes();
    }

    private void ClearPasswordBoxes()
    {
        SetupPassword.Clear();
        SetupConfirmPassword.Clear();
        SignInPassword.Clear();
        RecoveryNewPassword.Clear();
        RecoveryConfirmPassword.Clear();
        RequiredCurrentPassword.Clear();
        RequiredNewPassword.Clear();
        RequiredConfirmPassword.Clear();
    }
}
