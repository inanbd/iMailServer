using MailServer.Domain.Exceptions;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// A storage quota expressed in bytes, where zero means "unlimited".
/// </summary>
/// <remarks>
/// Modelling "unlimited" as a distinct state rather than as <c>null</c> or
/// <see cref="long.MaxValue"/> avoids two recurring bugs: null-handling scattered through
/// every usage-percentage calculation, and overflow when a sentinel maximum is added to a
/// real size.
/// </remarks>
public readonly record struct QuotaBytes : IComparable<QuotaBytes>
{
    public const long BytesPerKilobyte = 1024L;
    public const long BytesPerMegabyte = 1024L * 1024L;
    public const long BytesPerGigabyte = 1024L * 1024L * 1024L;

    /// <summary>Warning thresholds surfaced in the UI and in health checks.</summary>
    public static readonly int[] WarningThresholdPercentages = [80, 90, 100];

    private QuotaBytes(long bytes) => Bytes = bytes;

    /// <summary>Quota in bytes; zero means unlimited.</summary>
    public long Bytes { get; }

    /// <summary>True when no limit applies.</summary>
    public bool IsUnlimited => Bytes == 0;

    /// <summary>The unlimited quota.</summary>
    public static QuotaBytes Unlimited => new(0);

    public static QuotaBytes FromBytes(long bytes)
    {
        if (bytes < 0)
        {
            throw new InvalidValueObjectException(nameof(QuotaBytes), "a quota cannot be negative.");
        }

        return new QuotaBytes(bytes);
    }

    public static QuotaBytes FromMegabytes(long megabytes) =>
        FromBytes(checked(megabytes * BytesPerMegabyte));

    public static QuotaBytes FromGigabytes(long gigabytes) =>
        FromBytes(checked(gigabytes * BytesPerGigabyte));

    /// <summary>True when <paramref name="usedBytes"/> has reached or passed this quota.</summary>
    public bool IsExceededBy(long usedBytes) => !IsUnlimited && usedBytes >= Bytes;

    /// <summary>
    /// True when accepting <paramref name="additionalBytes"/> on top of
    /// <paramref name="usedBytes"/> would breach this quota. This, not
    /// <see cref="IsExceededBy"/>, is the check to run before accepting a message, so that a
    /// mailbox at 99% does not accept a 50 MB attachment.
    /// </summary>
    public bool WouldBeExceededBy(long usedBytes, long additionalBytes) =>
        !IsUnlimited && usedBytes + additionalBytes > Bytes;

    /// <summary>Percentage of the quota consumed; zero for an unlimited quota.</summary>
    public double PercentageUsed(long usedBytes)
    {
        if (IsUnlimited || Bytes == 0)
        {
            return 0d;
        }

        return Math.Round(usedBytes * 100d / Bytes, 2, MidpointRounding.AwayFromZero);
    }

    public int CompareTo(QuotaBytes other)
    {
        // Unlimited sorts above every finite quota.
        if (IsUnlimited)
        {
            return other.IsUnlimited ? 0 : 1;
        }

        return other.IsUnlimited ? -1 : Bytes.CompareTo(other.Bytes);
    }

    public override string ToString() => IsUnlimited ? "Unlimited" : FormatBytes(Bytes);

    /// <summary>Formats a byte count for display using binary units.</summary>
    public static string FormatBytes(long bytes) => bytes switch
    {
        >= BytesPerGigabyte => $"{bytes / (double)BytesPerGigabyte:0.##} GB",
        >= BytesPerMegabyte => $"{bytes / (double)BytesPerMegabyte:0.##} MB",
        >= BytesPerKilobyte => $"{bytes / (double)BytesPerKilobyte:0.##} KB",
        _ => $"{bytes} B",
    };
}
