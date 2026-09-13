using CommunityToolkit.Mvvm.ComponentModel;
using MailServer.Ipc.Client;
using Microsoft.Extensions.Logging;

namespace MailServer.Admin.ViewModels;

/// <summary>
/// Base for every page in the shell.
/// </summary>
/// <remarks>
/// <para>
/// <b>View models hold presentation state only.</b> Busy flags, the selected row, sort order,
/// error text to display. Business rules - "a domain cannot be deleted while it still has
/// mailboxes", "a domain needs a hostname before it can be enabled" - live in the Domain and
/// Application layers and reach the UI as typed errors over IPC.
/// </para>
/// <para>
/// That separation is not stylistic. A rule implemented in both the server and the UI will
/// eventually disagree with itself, and the copy the user sees is the wrong one to trust.
/// </para>
/// </remarks>
public abstract partial class PageViewModel(ILogger logger) : ObservableObject
{
    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial string? ErrorMessage { get; set; }

    /// <summary>
    /// Correlation id of the last failure, so an administrator can quote it when reporting a
    /// problem and an operator can find the full detail in the service log.
    /// </summary>
    [ObservableProperty]
    public partial string? ErrorCorrelationId { get; set; }

    /// <summary>Title shown in the shell header.</summary>
    public abstract string Title { get; }

    /// <summary>Loads the page's data. Called by the navigation service.</summary>
    public async Task LoadAsync()
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        ErrorMessage = null;
        ErrorCorrelationId = null;

        try
        {
            await OnLoadAsync().ConfigureAwait(true);
        }
        catch (IpcRequestException ex)
        {
            // A structured error from the service. Its message was written for an
            // administrator to read, so it is shown verbatim.
            logger.LogWarning(
                "{Page} could not load: {ErrorCode}.",
                GetType().Name,
                ex.Error.Code);

            ErrorMessage = ex.Message;
            ErrorCorrelationId = ex.CorrelationId;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "{Page} failed to load.", GetType().Name);
            ErrorMessage = $"An unexpected error occurred: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>The page's own load logic.</summary>
    protected abstract Task OnLoadAsync();

    /// <summary>
    /// Runs a command with the busy flag and error handling already applied.
    /// </summary>
    /// <remarks>
    /// Every page command routes through here, which is what guarantees the busy indicator is
    /// always cleared - including on the failure path, where forgetting it leaves the UI
    /// permanently disabled with no way back except a restart.
    /// </remarks>
    protected async Task ExecuteAsync(Func<Task> action, bool reloadAfter = true)
    {
        ArgumentNullException.ThrowIfNull(action);

        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        ErrorMessage = null;
        ErrorCorrelationId = null;

        try
        {
            await action().ConfigureAwait(true);

            if (reloadAfter)
            {
                await OnLoadAsync().ConfigureAwait(true);
            }
        }
        catch (IpcRequestException ex)
        {
            logger.LogWarning("{Page} command failed: {ErrorCode}.", GetType().Name, ex.Error.Code);

            ErrorMessage = ex.Error.ValidationErrors is { Count: > 0 } validation
                ? string.Join(Environment.NewLine, validation.SelectMany(kv => kv.Value))
                : ex.Message;

            ErrorCorrelationId = ex.CorrelationId;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "{Page} command failed unexpectedly.", GetType().Name);
            ErrorMessage = $"An unexpected error occurred: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
