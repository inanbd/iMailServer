using MailServer.Admin.ViewModels;

namespace MailServer.Admin.Services;

/// <summary>
/// Moves the shell between pages.
/// </summary>
/// <remarks>
/// Centralised so that the shell does not accumulate a switch over page names, and so that
/// view models can navigate without knowing what a <c>Window</c> is - which is what keeps
/// them unit-testable.
/// </remarks>
public interface INavigationService
{
    /// <summary>The view model currently displayed.</summary>
    PageViewModel? Current { get; }

    /// <summary>Raised after navigation completes.</summary>
    event EventHandler<PageViewModel>? Navigated;

    /// <summary>Navigates to a page, resolving its view model from the container.</summary>
    void NavigateTo<TViewModel>() where TViewModel : PageViewModel;

    /// <summary>Navigates to a page by its view-model type.</summary>
    void NavigateTo(Type viewModelType);
}
