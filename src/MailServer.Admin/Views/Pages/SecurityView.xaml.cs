using System.Windows.Controls;
using MailServer.Admin.ViewModels;

namespace MailServer.Admin.Views.Pages;

/// <summary>
/// Code-behind for the security page.
/// </summary>
/// <remarks>
/// Reads the <see cref="PasswordBox"/> values and hands them straight to the view model, for
/// the same reason as <see cref="AuthenticationOverlay"/>: <c>PasswordBox.Password</c> is not a
/// dependency property on purpose, and binding it would keep the plaintext alive in the binding
/// engine for the lifetime of the view.
/// </remarks>
public partial class SecurityView : UserControl
{
    public SecurityView() => InitializeComponent();

    private async void OnChangePassword(object sender, System.Windows.RoutedEventArgs e)
    {
        if (DataContext is not SecurityViewModel viewModel)
        {
            return;
        }

        await viewModel
            .ChangePasswordAsync(
                CurrentPassword.Password,
                NewPassword.Password,
                ConfirmPassword.Password,
                KeepOtherSessions.IsChecked == true)
            .ConfigureAwait(true);

        CurrentPassword.Clear();
        NewPassword.Clear();
        ConfirmPassword.Clear();
    }
}
