using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MailServer.Application.Security.Dtos;
using MailServer.Ipc.Client;
using MailServer.Ipc.Protocol;
using Microsoft.Extensions.Logging;

namespace MailServer.Admin.ViewModels;

/// <summary>Which authentication screen the overlay is showing.</summary>
public enum AuthenticationStage
{
    /// <summary>Asking the service whether setup is required.</summary>
    Connecting = 0,

    /// <summary>No administrator exists: create the master password.</summary>
    Setup = 1,

    /// <summary>Showing the recovery key, once, before continuing.</summary>
    ShowRecoveryKey = 2,

    /// <summary>Normal sign-in.</summary>
    SignIn = 3,

    /// <summary>Resetting the password with the recovery key.</summary>
    Recovery = 4,

    /// <summary>A password change is outstanding after a recovery reset.</summary>
    ChangeRequired = 5,

    /// <summary>Authenticated; the shell is usable.</summary>
    Authenticated = 6,
}

/// <summary>
/// Drives the authentication overlay: setup, sign-in, lock and recovery.
/// </summary>
/// <remarks>
/// <para>
/// <b>Holds no password field as an observable property.</b> WPF's <c>PasswordBox</c>
/// deliberately does not expose <c>Password</c> as a bindable dependency property, because a
/// bound string would sit in the binding engine and on the managed heap for as long as the
/// view lived. The view passes the value in as a method argument instead, and this class never
/// stores it.
/// </para>
/// <para>
/// Every rule — password strength, lockout, whether setup is permitted — is enforced by the
/// service. This class shows what the service says. It does not re-implement a single check,
/// because a UI-side copy of a security rule is a rule that will eventually disagree with the
/// one that actually matters.
/// </para>
/// </remarks>
public sealed partial class AuthenticationViewModel(
    IAdminGateway gateway,
    ILogger<AuthenticationViewModel> logger) : ObservableObject
{
    [ObservableProperty]
    public partial AuthenticationStage Stage { get; set; } = AuthenticationStage.Connecting;

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial string? ErrorMessage { get; set; }

    [ObservableProperty]
    public partial string? StatusMessage { get; set; }

    [ObservableProperty]
    public partial int MinimumPasswordLength { get; set; } = 12;

    [ObservableProperty]
    public partial bool IsLockedOut { get; set; }

    [ObservableProperty]
    public partial int LockoutSecondsRemaining { get; set; }

    /// <summary>
    /// The recovery key, held only while the "write this down" screen is showing.
    /// </summary>
    /// <remarks>
    /// Cleared by <see cref="AcknowledgeRecoveryKey"/>. Nothing in the product can display it
    /// again, because the service stored only an Argon2id hash of it.
    /// </remarks>
    [ObservableProperty]
    public partial string? RecoveryKeyToDisplay { get; set; }

    [ObservableProperty]
    public partial bool HasWrittenDownRecoveryKey { get; set; }

    /// <summary>The signed-in administrator, once authenticated.</summary>
    [ObservableProperty]
    public partial string? Administrator { get; set; }

    /// <summary>Idle seconds after which the console locks, as decided by the service.</summary>
    [ObservableProperty]
    public partial int IdleTimeoutSeconds { get; set; } = 600;

    /// <summary>Raised when authentication succeeds, so the shell can load itself.</summary>
    public event EventHandler? Authenticated;

    /// <summary>Raised when the session ends, so the shell can clear what it is showing.</summary>
    public event EventHandler? SignedOut;

    public bool IsAuthenticated => Stage == AuthenticationStage.Authenticated;

    /// <summary>Asks the service whether setup is required and shows the right screen.</summary>
    public async Task InitializeAsync()
    {
        IsBusy = true;
        ErrorMessage = null;

        try
        {
            SetupStatusDto status = await gateway.GetSetupStatusAsync().ConfigureAwait(true);

            MinimumPasswordLength = status.MinimumPasswordLength;
            IsLockedOut = status.IsLockedOut;
            LockoutSecondsRemaining = status.LockoutSecondsRemaining;

            Stage = status.RequiresSetup ? AuthenticationStage.Setup : AuthenticationStage.SignIn;

            StatusMessage = status.RequiresSetup
                ? "This server has not been configured. Create a master password to begin."
                : null;
        }
        catch (IpcRequestException ex)
        {
            logger.LogWarning("Could not reach the mail service: {ErrorCode}.", ex.Error.Code);
            ErrorMessage = ex.Message;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Could not determine the server's setup status.");
            ErrorMessage = $"Could not reach the AetherMail service: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>
    /// Completes first-run setup.
    /// </summary>
    /// <remarks>
    /// Passwords arrive as arguments from the view's <c>PasswordBox</c> controls rather than
    /// from bound properties; see the class remarks.
    /// </remarks>
    public Task CompleteSetupAsync(string password, string confirmPassword) =>
        RunAsync(async () =>
        {
            SetupResultDto result = await gateway
                .CompleteSetupAsync(password, confirmPassword)
                .ConfigureAwait(true);

            Administrator = result.Authentication.Administrator;
            IdleTimeoutSeconds = result.Authentication.IdleTimeoutSeconds;

            // Shown once, and only once. The service kept a hash; there is no second chance.
            RecoveryKeyToDisplay = result.RecoveryKey.RecoveryKey;
            HasWrittenDownRecoveryKey = false;
            Stage = AuthenticationStage.ShowRecoveryKey;
        });

    /// <summary>Signs in.</summary>
    public Task SignInAsync(string password) =>
        RunAsync(async () =>
        {
            AuthenticationResultDto result =
                await gateway.AuthenticateAsync(password).ConfigureAwait(true);

            Administrator = result.Administrator;
            IdleTimeoutSeconds = result.IdleTimeoutSeconds;
            IsLockedOut = false;
            LockoutSecondsRemaining = 0;

            if (result.MustChangePassword)
            {
                // The session is valid but owes a password change. The service will refuse
                // every other command until it is done, so the UI goes straight there.
                Stage = AuthenticationStage.ChangeRequired;

                StatusMessage =
                    "The password was reset with a recovery key. Choose a new master password " +
                    "to continue.";

                return;
            }

            Stage = AuthenticationStage.Authenticated;
            StatusMessage = null;
            Authenticated?.Invoke(this, EventArgs.Empty);
        });

    /// <summary>Resets the password using the recovery key, and shows the replacement key.</summary>
    public Task ResetWithRecoveryKeyAsync(
        string recoveryKey,
        string newPassword,
        string confirmPassword) =>
        RunAsync(async () =>
        {
            RecoveryKeyDto replacement = await gateway
                .ResetPasswordWithRecoveryKeyAsync(recoveryKey, newPassword, confirmPassword)
                .ConfigureAwait(true);

            // A replacement is issued in the same operation, so the server is never left
            // without a recovery route. It too is shown only once.
            RecoveryKeyToDisplay = replacement.RecoveryKey;
            HasWrittenDownRecoveryKey = false;
            Stage = AuthenticationStage.ShowRecoveryKey;

            StatusMessage =
                "The master password was reset. A new recovery key has been issued - the " +
                "previous one no longer works.";
        });

    /// <summary>Changes the password while one is outstanding after a recovery reset.</summary>
    public Task CompleteRequiredChangeAsync(
        string currentPassword,
        string newPassword,
        string confirmPassword) =>
        RunAsync(async () =>
        {
            await gateway
                .ChangeMasterPasswordAsync(currentPassword, newPassword, confirmPassword)
                .ConfigureAwait(true);

            // The change revoked every session including this one, so sign in again with the
            // new password rather than pretending to still be authenticated.
            Stage = AuthenticationStage.SignIn;

            StatusMessage =
                "The master password was changed. Sign in with the new password to continue.";
        });

    /// <summary>Dismisses the recovery key screen and continues into the shell.</summary>
    [RelayCommand]
    private void AcknowledgeRecoveryKey()
    {
        if (!HasWrittenDownRecoveryKey)
        {
            ErrorMessage =
                "Confirm that the recovery key has been recorded. It cannot be shown again.";
            return;
        }

        // Dropped from memory as soon as the administrator says they have it.
        RecoveryKeyToDisplay = null;
        ErrorMessage = null;

        if (Stage == AuthenticationStage.ShowRecoveryKey && gateway.HasSession)
        {
            Stage = AuthenticationStage.Authenticated;
            Authenticated?.Invoke(this, EventArgs.Empty);
        }
        else
        {
            // Reached after a recovery reset, which revoked every session.
            Stage = AuthenticationStage.SignIn;
        }
    }

    [RelayCommand]
    private void ShowRecovery()
    {
        Stage = AuthenticationStage.Recovery;
        ErrorMessage = null;

        StatusMessage =
            "Enter the recovery key issued when this server was configured. It can be used " +
            "once; a replacement will be issued.";
    }

    [RelayCommand]
    private void CancelRecovery()
    {
        Stage = AuthenticationStage.SignIn;
        ErrorMessage = null;
        StatusMessage = null;
    }

    /// <summary>Locks the console, ending the session on the server as well.</summary>
    public async Task LockAsync(bool isAutoLock)
    {
        try
        {
            await gateway.SignOutAsync(isAutoLock).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            // The session may already be gone - which is exactly when locking is most likely.
            // Failing to tell the server must never stop the console locking locally.
            logger.LogDebug(ex, "Sign-out reported an error while locking.");
        }

        Administrator = null;
        Stage = AuthenticationStage.SignIn;
        ErrorMessage = null;

        StatusMessage = isAutoLock
            ? "The console locked after a period of inactivity."
            : null;

        SignedOut?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Returns to the sign-in screen because the service rejected the session.
    /// </summary>
    /// <remarks>
    /// Called by the shell when any request comes back <see cref="IpcErrorKind.Unauthenticated"/>.
    /// No sign-out is attempted: the session is already gone, and asking the server to revoke
    /// something it has forgotten would only produce another rejection.
    /// </remarks>
    public void OnSessionRejected(string? message)
    {
        Administrator = null;
        Stage = AuthenticationStage.SignIn;
        StatusMessage = message ?? "The session ended. Sign in to continue.";
        SignedOut?.Invoke(this, EventArgs.Empty);
    }

    private async Task RunAsync(Func<Task> action)
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        ErrorMessage = null;

        try
        {
            await action().ConfigureAwait(true);
        }
        catch (IpcRequestException ex)
        {
            // The service's message is shown verbatim: it was written for an administrator to
            // read, and it has already decided what may safely be revealed. A failed sign-in
            // says only "the master password is not correct", whatever the real reason.
            ErrorMessage = ex.Error.ValidationErrors is { Count: > 0 } validation
                ? string.Join(Environment.NewLine, validation.SelectMany(v => v.Value))
                : ex.Message;

            if (ex.Error.Code == "security.account.locked_out")
            {
                IsLockedOut = true;
            }

            logger.LogWarning("Authentication step failed: {ErrorCode}.", ex.Error.Code);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An unexpected error occurred during authentication.");
            ErrorMessage = $"An unexpected error occurred: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
