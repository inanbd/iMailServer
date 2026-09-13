using MailServer.Admin.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace MailServer.Admin.Services;

/// <summary>Resolves page view models from the container and publishes navigation.</summary>
public sealed class NavigationService(IServiceProvider services) : INavigationService
{
    public PageViewModel? Current { get; private set; }

    public event EventHandler<PageViewModel>? Navigated;

    public void NavigateTo<TViewModel>() where TViewModel : PageViewModel =>
        NavigateTo(typeof(TViewModel));

    public void NavigateTo(Type viewModelType)
    {
        ArgumentNullException.ThrowIfNull(viewModelType);

        if (!typeof(PageViewModel).IsAssignableFrom(viewModelType))
        {
            throw new ArgumentException(
                $"{viewModelType.Name} is not a {nameof(PageViewModel)}.",
                nameof(viewModelType));
        }

        // Resolved from the container each time rather than cached, so a page always opens
        // with fresh state. An administration console showing stale counts from the last
        // time a page was visited is worse than a brief load.
        PageViewModel viewModel = (PageViewModel)services.GetRequiredService(viewModelType);

        Current = viewModel;
        Navigated?.Invoke(this, viewModel);

        // Fire-and-forget is deliberate and contained: OnNavigatedToAsync is the page's own
        // load, it catches its own exceptions into its ErrorMessage, and navigation must not
        // block the UI thread waiting for a network round trip to the service.
        _ = viewModel.LoadAsync();
    }
}
