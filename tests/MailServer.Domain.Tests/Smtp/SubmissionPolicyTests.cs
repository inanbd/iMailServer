using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Tests.Smtp;

/// <summary>
/// The submission policy: whether an authenticated client may use the sender it asked for.
/// </summary>
/// <remarks>
/// Authentication proves who is connecting; it does not entitle them to claim anybody's address.
/// Without this, one stolen password sends as every colleague — from the real server, over the
/// real TLS, passing SPF, DKIM and DMARC, because the mail genuinely is from this domain.
/// </remarks>
public sealed class SubmissionPolicyTests
{
    private static readonly SubmissionPolicy Policy = new();

    private static EmailAddress Address(string value) => EmailAddress.Parse(value);

    private static SubmissionPolicy.Result Evaluate(
        string authenticated,
        string? reversePath,
        params string[] mayActAs)
    {
        HashSet<string> permitted = new(mayActAs, StringComparer.OrdinalIgnoreCase);

        return Policy.Evaluate(
            new SubmissionContext(
                Address(authenticated),
                reversePath is null ? null : Address(reversePath)),
            claimed => permitted.Contains(claimed.Value));
    }

    [Fact]
    public void A_mailbox_may_send_as_itself()
    {
        Evaluate("alice@example.com", "alice@example.com").IsPermitted.ShouldBeTrue();
    }

    [Fact]
    public void Sending_as_itself_is_matched_case_insensitively()
    {
        // Addresses are compared on their normalised form. A client that capitalises its own
        // address differently from the directory is not forging anything.
        Evaluate("alice@example.com", "Alice@Example.COM").IsPermitted.ShouldBeTrue();
    }

    [Fact]
    public void A_mailbox_may_not_send_as_a_colleague()
    {
        // The case that matters. One stolen password must not become every address in the
        // organisation.
        SubmissionPolicy.Result result = Evaluate("alice@example.com", "ceo@example.com");

        result.IsPermitted.ShouldBeFalse();
        result.Reason.ShouldContain("may not send as");
    }

    [Fact]
    public void A_mailbox_may_not_send_as_an_address_in_another_domain()
    {
        Evaluate("alice@example.com", "someone@elsewhere.example").IsPermitted.ShouldBeFalse();
    }

    [Fact]
    public void An_alias_the_mailbox_is_behind_may_be_used()
    {
        // Someone whose mail arrives at both alice@ and sales@ expects to reply from either.
        // Refusing would make an alias useful only for receiving.
        Evaluate("alice@example.com", "sales@example.com", "sales@example.com").IsPermitted.ShouldBeTrue();
    }

    [Fact]
    public void An_alias_the_mailbox_is_not_behind_may_not_be_used()
    {
        Evaluate("alice@example.com", "payroll@example.com", "sales@example.com").IsPermitted.ShouldBeFalse();
    }

    [Fact]
    public void The_null_reverse_path_is_refused_on_submission()
    {
        // "<>" is a BOUNCE's sender. A mail client does not send bounces - only an MTA does, and
        // an MTA does not authenticate to a submission port. Accepting it would let an
        // authenticated client emit mail that cannot itself be bounced, which is backscatter.
        SubmissionPolicy.Result result = Evaluate("alice@example.com", reversePath: null);

        result.IsPermitted.ShouldBeFalse();
        result.Reason.ShouldContain("null reverse path");
    }

    [Fact]
    public void The_null_reverse_path_is_refused_even_when_everything_is_permitted()
    {
        // The lookup is not even consulted: a null path has no address to check.
        Policy.Evaluate(
            new SubmissionContext(Address("alice@example.com"), null),
            _ => true).IsPermitted.ShouldBeFalse();
    }

    [Fact]
    public void Deny_is_the_fall_through()
    {
        // Nothing permits a sender except the mailbox's own address or an explicit entitlement.
        // A lookup that refuses everything must refuse everything.
        foreach (string claimed in (string[])
        [
            "someone@example.com",
            "alice@elsewhere.example",
            "\"alice@example.com\"@elsewhere.example",
            "alice@example.com.elsewhere.example",
        ])
        {
            Policy.Evaluate(
                new SubmissionContext(Address("alice@example.com"), Address(claimed)),
                _ => false).IsPermitted.ShouldBeFalse($"'{claimed}' was permitted.");
        }
    }

    [Fact]
    public void A_refusal_names_what_to_change()
    {
        // The usual cause is a client configured with one address and authenticating with
        // another - an ordinary misconfiguration that an unexplained refusal turns into a
        // support call.
        SubmissionPolicy.Result result = Evaluate("alice@example.com", "ceo@example.com");

        result.Reason.ShouldContain("alice@example.com");
        result.Reason.ShouldContain("ceo@example.com");
        result.Reason.ShouldContain("alias");
    }

    [Fact]
    public void The_product_states_outright_that_authentication_is_not_a_blank_cheque()
    {
        SubmissionPolicy.MayAuthenticatedSenderUseAnyAddress.ShouldBeFalse();
    }

    [Fact]
    public void The_entitlement_lookup_is_asked_about_the_claimed_sender()
    {
        // A policy that asked about the authenticated mailbox instead would permit everything,
        // because a mailbox always owns itself.
        List<string> asked = [];

        Policy.Evaluate(
            new SubmissionContext(Address("alice@example.com"), Address("ceo@example.com")),
            claimed =>
            {
                asked.Add(claimed.Value);
                return false;
            });

        asked.ShouldHaveSingleItem().ShouldBe("ceo@example.com");
    }
}
