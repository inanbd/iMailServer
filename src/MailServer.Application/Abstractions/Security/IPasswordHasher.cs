using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Security;

/// <summary>The outcome of verifying a candidate against a stored verifier.</summary>
/// <param name="IsValid">True when the candidate matches.</param>
/// <param name="NeedsRehash">
/// True when the stored verifier used weaker work factors than current policy. Only ever true
/// alongside <c>IsValid</c>, because a rehash needs the plaintext, which is available only on a
/// successful verification.
/// </param>
public readonly record struct PasswordVerificationResult(bool IsValid, bool NeedsRehash);

/// <summary>
/// Hashes and verifies passwords.
/// </summary>
/// <remarks>
/// <para>
/// <b>One-way. Never reversible.</b> Anything the server must be able to read back — DKIM keys,
/// ACME account keys, smarthost credentials — goes through <see cref="ISecretProtector"/>
/// instead. A password is not in that category, and the two interfaces are deliberately
/// separate so the distinction cannot be blurred by picking the convenient method.
/// </para>
/// <para>
/// Implementations must compare in constant time. A comparison that returns early on the first
/// differing byte leaks the length of the correct prefix, and over enough attempts that is
/// enough to recover the verifier.
/// </para>
/// <para>
/// Implementations must also be deliberately slow. That is the entire point of Argon2: the
/// cost that makes a legitimate sign-in take a fraction of a second makes an offline cracking
/// run against a stolen database take years.
/// </para>
/// </remarks>
public interface IPasswordHasher
{
    /// <summary>Algorithm and parameters in use, for diagnostics and for the UI.</summary>
    string Describe();

    /// <summary>Hashes a password with the current work factors.</summary>
    PasswordHash Hash(string password);

    /// <summary>
    /// Verifies a candidate against a stored verifier.
    /// </summary>
    /// <remarks>
    /// Returns a result rather than throwing on a malformed stored value: on the
    /// authentication path, a corrupt row must produce an ordinary authentication failure, not
    /// an exception whose different shape or timing would distinguish it.
    /// </remarks>
    PasswordVerificationResult Verify(string candidate, PasswordHash stored);

    /// <summary>
    /// Performs equivalent work and returns false, for the case where no account exists.
    /// </summary>
    /// <remarks>
    /// <b>This is the defence against username enumeration by timing.</b> If a sign-in against
    /// a nonexistent account returned immediately while a real one spent 200 ms in Argon2, the
    /// difference would be trivially measurable and would reveal which accounts exist. The
    /// authentication path calls this so both cases cost the same.
    /// </remarks>
    bool VerifyAgainstDummy(string candidate);
}
