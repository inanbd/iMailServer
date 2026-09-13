using System.Diagnostics;
using MailServer.Application.Abstractions.Security;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MailServer.SecurityTests;

/// <summary>
/// Password hashing properties.
/// </summary>
/// <remarks>
/// Work factors are lowered for the test run (8 MiB, 1 pass) so the suite completes quickly.
/// The properties under test — salting, constant-time comparison, rehash detection, equal cost
/// for a missing account — are all independent of the factors chosen, and the production
/// defaults are asserted separately in <see cref="DefaultsAreStrong"/>.
/// </remarks>
public sealed class PasswordHashingTests
{
    private static Argon2PasswordHasher CreateHasher(
        int memoryKib = 8 * 1024,
        int iterations = 1,
        int parallelism = 1)
    {
        MailServerOptions options = new()
        {
            Security = new SecurityOptions
            {
                Argon2MemoryKib = memoryKib,
                Argon2Iterations = iterations,
                Argon2Parallelism = parallelism,
            },
        };

        return new Argon2PasswordHasher(
            Options.Create(options),
            NullLogger<Argon2PasswordHasher>.Instance);
    }

    [Fact]
    public void A_correct_password_verifies()
    {
        Argon2PasswordHasher hasher = CreateHasher();

        PasswordHash hash = hasher.Hash("correct horse battery staple");

        hasher.Verify("correct horse battery staple", hash).IsValid.ShouldBeTrue();
    }

    [Theory]
    [InlineData("wrong password entirely")]
    [InlineData("correct horse battery stapl")]   // one character short
    [InlineData("correct horse battery staple ")] // one trailing space
    [InlineData("Correct horse battery staple")]  // case differs
    [InlineData("")]
    public void An_incorrect_password_does_not_verify(string candidate)
    {
        Argon2PasswordHasher hasher = CreateHasher();

        PasswordHash hash = hasher.Hash("correct horse battery staple");

        hasher.Verify(candidate, hash).IsValid.ShouldBeFalse();
    }

    [Fact]
    public void The_same_password_hashes_differently_every_time()
    {
        // A fresh random salt per hash. Without it, two administrators choosing the same
        // password would produce identical verifiers, and a stolen database would reveal that
        // fact - plus let one precomputed table crack both.
        Argon2PasswordHasher hasher = CreateHasher();

        PasswordHash first = hasher.Hash("same password");
        PasswordHash second = hasher.Hash("same password");

        first.Encoded.ShouldNotBe(second.Encoded);
        first.Salt.ShouldNotBe(second.Salt);

        // Both still verify.
        hasher.Verify("same password", first).IsValid.ShouldBeTrue();
        hasher.Verify("same password", second).IsValid.ShouldBeTrue();
    }

    [Fact]
    public void The_encoded_form_never_contains_the_plaintext()
    {
        Argon2PasswordHasher hasher = CreateHasher();

        const string Secret = "AVeryDistinctivePassphrase";

        hasher.Hash(Secret).Encoded.ShouldNotContain(Secret);
    }

    [Fact]
    public void ToString_does_not_leak_the_verifier()
    {
        // A verifier interpolated into a log line or an exception message by an incidental
        // ToString() is an offline-cracking gift.
        Argon2PasswordHasher hasher = CreateHasher();

        PasswordHash hash = hasher.Hash("some password");

        hash.ToString().ShouldNotContain(Convert.ToBase64String(hash.Hash).TrimEnd('='));
        hash.ToString().ShouldContain("argon2id");
    }

    [Fact]
    public void The_encoding_round_trips_through_storage()
    {
        Argon2PasswordHasher hasher = CreateHasher();

        PasswordHash original = hasher.Hash("round trip");

        // Exactly what the database column holds and returns.
        PasswordHash reloaded = PasswordHash.Parse(original.Encoded);

        reloaded.Algorithm.ShouldBe(original.Algorithm);
        reloaded.MemoryKib.ShouldBe(original.MemoryKib);
        reloaded.Iterations.ShouldBe(original.Iterations);
        reloaded.Parallelism.ShouldBe(original.Parallelism);
        reloaded.Salt.ShouldBe(original.Salt);
        reloaded.Hash.ShouldBe(original.Hash);

        hasher.Verify("round trip", reloaded).IsValid.ShouldBeTrue();
    }

    [Fact]
    public void A_hash_made_with_weaker_factors_still_verifies_and_is_flagged_for_rehash()
    {
        // The reason work factors travel with the hash: raising them must not lock everybody
        // out, and the upgrade happens at the one moment the plaintext is available.
        Argon2PasswordHasher weak = CreateHasher(memoryKib: 8 * 1024, iterations: 1);
        PasswordHash oldHash = weak.Hash("unchanged password");

        Argon2PasswordHasher strong = CreateHasher(memoryKib: 16 * 1024, iterations: 2);

        PasswordVerificationResult result = strong.Verify("unchanged password", oldHash);

        result.IsValid.ShouldBeTrue();
        result.NeedsRehash.ShouldBeTrue();
    }

    [Fact]
    public void A_hash_made_with_current_factors_is_not_flagged_for_rehash()
    {
        Argon2PasswordHasher hasher = CreateHasher();

        PasswordVerificationResult result =
            hasher.Verify("current", hasher.Hash("current"));

        result.IsValid.ShouldBeTrue();
        result.NeedsRehash.ShouldBeFalse();
    }

    [Fact]
    public void A_failed_verification_never_reports_needing_a_rehash()
    {
        // NeedsRehash is only meaningful alongside a success, because rehashing requires the
        // plaintext to be correct. Reporting it on a failure would invite a caller to rehash
        // a wrong password into the account.
        Argon2PasswordHasher weak = CreateHasher(memoryKib: 8 * 1024, iterations: 1);
        Argon2PasswordHasher strong = CreateHasher(memoryKib: 16 * 1024, iterations: 2);

        PasswordVerificationResult result =
            strong.Verify("wrong", weak.Hash("right"));

        result.IsValid.ShouldBeFalse();
        result.NeedsRehash.ShouldBeFalse();
    }

    [Fact]
    public void A_corrupt_stored_hash_produces_a_clean_failure_rather_than_an_exception()
    {
        // On the authentication path a corrupt row must behave like a wrong password. An
        // exception would have a different shape and a different timing, either of which
        // distinguishes it.
        PasswordHash.TryParse("not a phc string", out _).ShouldBeFalse();
        PasswordHash.TryParse("$argon2id$v=19$m=0,t=0,p=0$$", out _).ShouldBeFalse();
        PasswordHash.TryParse(null, out _).ShouldBeFalse();
        PasswordHash.TryParse(new string('x', 5000), out _).ShouldBeFalse();
    }

    [Fact]
    public void Verification_against_a_missing_account_costs_the_same_as_a_real_one()
    {
        // THE defence against username and setup-state enumeration by timing. If a sign-in
        // against an unconfigured server returned in microseconds while a real one spent
        // ~100 ms in Argon2, any client could measure the difference.
        //
        // Asserted as an order of magnitude rather than a tight bound: this runs on shared CI
        // hardware, and a strict comparison would be flaky without proving anything more.
        Argon2PasswordHasher hasher = CreateHasher();
        PasswordHash real = hasher.Hash("a password");

        // Warm up, so JIT and first-allocation costs do not land on the measured runs.
        hasher.Verify("x", real);
        hasher.VerifyAgainstDummy("x");

        Stopwatch realTimer = Stopwatch.StartNew();
        for (int i = 0; i < 3; i++)
        {
            hasher.Verify("wrong password", real);
        }

        realTimer.Stop();

        Stopwatch dummyTimer = Stopwatch.StartNew();
        for (int i = 0; i < 3; i++)
        {
            hasher.VerifyAgainstDummy("wrong password");
        }

        dummyTimer.Stop();

        double ratio = dummyTimer.Elapsed.TotalMilliseconds /
                       Math.Max(1, realTimer.Elapsed.TotalMilliseconds);

        ratio.ShouldBeInRange(
            0.2,
            5.0,
            "verification against a missing account must cost roughly the same as a real one, " +
            "otherwise the difference reveals whether an account exists");
    }

    [Fact]
    public void VerifyAgainstDummy_always_reports_failure() =>
        CreateHasher().VerifyAgainstDummy("anything at all").ShouldBeFalse();

    [Fact]
    public void DefaultsAreStrong()
    {
        // The production defaults, asserted explicitly so that lowering them to speed up a
        // test run or a sign-in is a visible, deliberate change rather than a quiet one.
        SecurityOptions defaults = new();

        defaults.Argon2MemoryKib.ShouldBe(65_536, "RFC 9106 recommends 64 MiB for this profile");
        defaults.Argon2Iterations.ShouldBeGreaterThanOrEqualTo(3);
        defaults.Argon2Parallelism.ShouldBeGreaterThanOrEqualTo(1);
        defaults.MinimumPasswordLength.ShouldBeGreaterThanOrEqualTo(12);
    }

    [Fact]
    public void The_algorithm_is_argon2id_not_argon2i_or_argon2d()
    {
        // Argon2d resists GPUs but leaks through side channels; Argon2i is the reverse.
        // Argon2id is the hybrid RFC 9106 recommends for password hashing.
        CreateHasher().Hash("x").Algorithm.ShouldBe("argon2id");
        CreateHasher().Describe().ShouldStartWith("argon2id");
    }
}
