using System.Windows.Controls;

namespace MailServer.Admin.Views.Pages;

/// <summary>
/// Code-behind for <c>DeliverabilityView</c>: the generated <c>InitializeComponent</c> call and
/// nothing else.
/// </summary>
/// <remarks>
/// Every behaviour on this page is a command on <c>DeliverabilityViewModel</c> — including the
/// delivery test, which is the one action here that sends real mail. Keeping it a command rather
/// than a click handler is what lets it be tested without a UI thread.
/// </remarks>
public partial class DeliverabilityView : UserControl
{
    public DeliverabilityView() => InitializeComponent();
}
