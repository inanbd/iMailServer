using MailServer.Domain.Enums;
using MailServer.Domain.Imap;
using MailServer.Domain.ValueObjects;

namespace MailServer.Imap.Tests;

public sealed class ImapSessionContextTests
{
    private static readonly DateTimeOffset Start = new(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

    private static ImapSessionContext Context(bool isTlsActive = false) =>
        new(IpAddressValue.Parse("198.51.100.20"), Start, isTlsActive);

    private static ImapSessionContext AuthenticatedContext()
    {
        ImapSessionContext context = Context(isTlsActive: true);
        context.Authenticate(new MailboxId(Guid.NewGuid()), EmailAddress.Parse("alice@example.com"));
        return context;
    }

    // ---------------------------------------------------------------------------------------
    // Starting state.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void A_new_session_starts_not_authenticated_with_no_selection()
    {
        ImapSessionContext context = Context();

        context.State.ShouldBe(ImapSessionState.NotAuthenticated);
        context.AuthenticatedMailbox.ShouldBeNull();
        context.AuthenticatedMailboxId.ShouldBeNull();
        context.SelectedFolderId.ShouldBeNull();
        context.FailedAuthenticationAttempts.ShouldBe(0);
    }

    [Fact]
    public void A_session_on_the_implicit_tls_listener_starts_with_tls_already_active()
    {
        Context(isTlsActive: true).IsTlsActive.ShouldBeTrue();
    }

    // ---------------------------------------------------------------------------------------
    // The STARTTLS handshake.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_tls_handshake_activates_tls()
    {
        ImapSessionContext context = Context();

        context.CompleteTlsHandshake();

        context.IsTlsActive.ShouldBeTrue();
    }

    [Fact]
    public void A_second_tls_handshake_is_refused()
    {
        ImapSessionContext context = Context(isTlsActive: true);

        Should.Throw<InvalidOperationException>(() => context.CompleteTlsHandshake());
    }

    [Fact]
    public void The_tls_handshake_does_not_disturb_the_remote_address_or_start_time()
    {
        // The transport's own facts, not anything the client said - nothing about them should
        // be reachable from a client-controlled event.
        ImapSessionContext context = Context();

        context.CompleteTlsHandshake();

        context.RemoteAddress.Value.ShouldBe("198.51.100.20");
        context.StartedAt.ShouldBe(Start);
    }

    // ---------------------------------------------------------------------------------------
    // Authenticate: LOGIN/AUTHENTICATE.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Authenticating_without_tls_is_refused()
    {
        ImapSessionContext context = Context(isTlsActive: false);

        Should.Throw<InvalidOperationException>(
            () => context.Authenticate(new MailboxId(Guid.NewGuid()), EmailAddress.Parse("alice@example.com")));

        context.State.ShouldBe(ImapSessionState.NotAuthenticated);
        context.AuthenticatedMailbox.ShouldBeNull();
    }

    [Fact]
    public void A_successful_authentication_records_the_mailbox_and_moves_to_authenticated()
    {
        ImapSessionContext context = Context(isTlsActive: true);
        MailboxId mailboxId = new(Guid.NewGuid());
        EmailAddress address = EmailAddress.Parse("alice@example.com");

        context.Authenticate(mailboxId, address);

        context.State.ShouldBe(ImapSessionState.Authenticated);
        context.AuthenticatedMailboxId.ShouldBe(mailboxId);
        context.AuthenticatedMailbox.ShouldBe(address);
    }

    [Fact]
    public void Authenticating_twice_is_refused()
    {
        ImapSessionContext context = AuthenticatedContext();

        Should.Throw<InvalidOperationException>(
            () => context.Authenticate(new MailboxId(Guid.NewGuid()), EmailAddress.Parse("mallory@example.com")));
    }

    [Fact]
    public void Authenticating_while_a_mailbox_is_selected_is_refused()
    {
        ImapSessionContext context = AuthenticatedContext();
        context.Select(MailboxFolderId.New(), uidValidity: 1, readOnly: false);

        Should.Throw<InvalidOperationException>(
            () => context.Authenticate(new MailboxId(Guid.NewGuid()), EmailAddress.Parse("mallory@example.com")));
    }

    [Fact]
    public void Failed_authentication_attempts_accumulate_and_are_never_refunded()
    {
        ImapSessionContext context = Context(isTlsActive: true);

        context.RecordFailedAuthentication();
        context.RecordFailedAuthentication();
        int third = context.RecordFailedAuthentication();

        third.ShouldBe(3);
        context.FailedAuthenticationAttempts.ShouldBe(3);

        context.Authenticate(new MailboxId(Guid.NewGuid()), EmailAddress.Parse("alice@example.com"));

        context.FailedAuthenticationAttempts.ShouldBe(3);
    }

    // ---------------------------------------------------------------------------------------
    // SELECT / EXAMINE / deselection.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Selecting_before_authentication_is_refused()
    {
        ImapSessionContext context = Context(isTlsActive: true);

        Should.Throw<InvalidOperationException>(
            () => context.Select(MailboxFolderId.New(), uidValidity: 1, readOnly: false));
    }

    [Fact]
    public void Selecting_a_folder_moves_to_selected_and_records_its_uidvalidity()
    {
        ImapSessionContext context = AuthenticatedContext();
        MailboxFolderId folderId = MailboxFolderId.New();

        context.Select(folderId, uidValidity: 1234, readOnly: false);

        context.State.ShouldBe(ImapSessionState.Selected);
        context.SelectedFolderId.ShouldBe(folderId);
        context.SelectedFolderUidValidity.ShouldBe(1234);
        context.IsSelectedReadOnly.ShouldBeFalse();
    }

    [Fact]
    public void Examine_selects_read_only()
    {
        ImapSessionContext context = AuthenticatedContext();

        context.Select(MailboxFolderId.New(), uidValidity: 1, readOnly: true);

        context.IsSelectedReadOnly.ShouldBeTrue();
    }

    [Fact]
    public void Selecting_a_second_folder_replaces_the_first_without_needing_an_explicit_close()
    {
        // RFC 3501 §6.3.1: SELECT automatically deselects any currently selected mailbox before
        // attempting the new selection.
        ImapSessionContext context = AuthenticatedContext();
        context.Select(MailboxFolderId.New(), uidValidity: 1, readOnly: false);

        MailboxFolderId second = MailboxFolderId.New();
        context.Select(second, uidValidity: 2, readOnly: true);

        context.State.ShouldBe(ImapSessionState.Selected);
        context.SelectedFolderId.ShouldBe(second);
        context.SelectedFolderUidValidity.ShouldBe(2);
        context.IsSelectedReadOnly.ShouldBeTrue();
    }

    [Fact]
    public void Deselecting_returns_to_authenticated_and_clears_the_selection()
    {
        ImapSessionContext context = AuthenticatedContext();
        context.Select(MailboxFolderId.New(), uidValidity: 5, readOnly: false);

        context.Deselect();

        context.State.ShouldBe(ImapSessionState.Authenticated);
        context.SelectedFolderId.ShouldBeNull();
        context.SelectedFolderUidValidity.ShouldBe(0);
        context.IsSelectedReadOnly.ShouldBeFalse();
    }

    [Fact]
    public void Deselecting_an_already_authenticated_session_is_a_harmless_no_op()
    {
        ImapSessionContext context = AuthenticatedContext();

        context.Deselect();

        context.State.ShouldBe(ImapSessionState.Authenticated);
    }

    [Fact]
    public void Authentication_survives_deselection()
    {
        ImapSessionContext context = AuthenticatedContext();
        EmailAddress? mailbox = context.AuthenticatedMailbox;
        context.Select(MailboxFolderId.New(), uidValidity: 1, readOnly: false);

        context.Deselect();

        context.AuthenticatedMailbox.ShouldBe(mailbox);
    }

    // ---------------------------------------------------------------------------------------
    // LOGOUT.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Logout_from_selected_clears_the_selection_and_moves_to_logout()
    {
        ImapSessionContext context = AuthenticatedContext();
        context.Select(MailboxFolderId.New(), uidValidity: 1, readOnly: false);

        context.Logout();

        context.State.ShouldBe(ImapSessionState.Logout);
        context.SelectedFolderId.ShouldBeNull();
    }

    [Fact]
    public void Logout_is_legal_from_not_authenticated()
    {
        ImapSessionContext context = Context();

        context.Logout();

        context.State.ShouldBe(ImapSessionState.Logout);
    }
}
