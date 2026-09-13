namespace MailServer.Application.Abstractions.Security;

/// <summary>
/// Encrypts and decrypts secrets at rest.
/// </summary>
/// <remarks>
/// <para>
/// Protects DKIM private keys, ACME account keys, certificate passphrases, SQL
/// authentication passwords, smarthost credentials, and the SRS and unsubscribe HMAC keys.
/// </para>
/// <para>
/// <b>This is not for passwords.</b> Mailbox and administrator passwords are hashed with
/// Argon2id and are never recoverable. Anything that goes through this interface is
/// something the server itself must be able to read back; a password is not.
/// </para>
/// <para>
/// The production implementation is DPAPI at machine scope with additional entropy held in
/// an ACL-protected file, so a copied database alone is not enough to recover secrets.
/// </para>
/// </remarks>
public interface ISecretProtector
{
    /// <summary>Name of the active protection scheme, for diagnostics and for backup metadata.</summary>
    string SchemeName { get; }

    /// <summary>True when this implementation is suitable for production use.</summary>
    bool IsProductionGrade { get; }

    /// <summary>Protects a secret. The result is opaque and safe to store.</summary>
    byte[] Protect(ReadOnlySpan<byte> plaintext);

    /// <summary>Unprotects a secret produced by <see cref="Protect"/>.</summary>
    byte[] Unprotect(ReadOnlySpan<byte> protectedData);

    /// <summary>Protects a UTF-8 string, returning Base64 for convenient storage.</summary>
    string ProtectString(string plaintext);

    /// <summary>Unprotects a Base64 payload produced by <see cref="ProtectString"/>.</summary>
    string UnprotectString(string protectedBase64);
}
