using System.Windows;
using System.Windows.Controls;
using MailServer.Admin.ViewModels;

namespace MailServer.Admin.Views.Pages;

/// <summary>
/// Code-behind for <c>MailboxesView</c>.
/// </summary>
/// <remarks>
/// <para>
/// The two handlers here exist for one reason: <see cref="PasswordBox.Password"/> is not a
/// dependency property, so it cannot be bound. That is deliberate on WPF's part — binding it
/// would place the plaintext in the binding engine, where it outlives the operation and is
/// visible to anything that can walk the visual tree.
/// </para>
/// <para>
/// The handlers therefore read the value at the moment the button is pressed, pass it as a
/// method argument, and clear the box. Nothing else in this file does any work; every other
/// behaviour on the page is a command on the view model.
/// </para>
/// </remarks>
public partial class MailboxesView : UserControl
{
    public MailboxesView() => InitializeComponent();

    private MailboxesViewModel? ViewModel => DataContext as MailboxesViewModel;

    private async void OnCreateMailbox(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } viewModel)
        {
            return;
        }

        string password = NewMailboxPasswordBox.Password;

        // Cleared before the await, not after: an await yields to the message loop, and the
        // box should not still hold a password while the operation is in flight.
        NewMailboxPasswordBox.Clear();

        await viewModel.CreateMailboxAsync(password);
    }

    private async void OnSetPassword(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } viewModel)
        {
            return;
        }

        string password = NewPasswordBox.Password;

        NewPasswordBox.Clear();

        await viewModel.SetPasswordAsync(password);
    }
}
