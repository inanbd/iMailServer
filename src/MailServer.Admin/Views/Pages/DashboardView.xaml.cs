using System.Windows.Controls;

namespace MailServer.Admin.Views.Pages;

/// <summary>
/// Code-behind for the dashboard.
/// </summary>
/// <remarks>
/// Empty, and deliberately so. All behaviour lives in <c>DashboardViewModel</c>, which is
/// testable without a UI thread. Code-behind that does work is code-behind that cannot be
/// tested.
/// </remarks>
public partial class DashboardView : UserControl
{
    public DashboardView() => InitializeComponent();
}
