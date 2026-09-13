namespace MailServer.Application.Common;

/// <summary>
/// One page of results plus the information a UI needs to page through the rest.
/// </summary>
/// <remarks>
/// <see cref="TotalCount"/> is nullable on purpose. Counting matching rows in a
/// multi-million-row queue is often more expensive than fetching the page itself, so query
/// services may skip the count and return null, and the UI then offers "next page" rather
/// than "page 7 of 412". Forcing every query to produce an exact total is a reliable way to
/// make a grid time out on a busy server.
/// </remarks>
public sealed record PagedResult<T>
{
    public PagedResult(IReadOnlyList<T> items, int page, int pageSize, long? totalCount)
    {
        ArgumentNullException.ThrowIfNull(items);
        ArgumentOutOfRangeException.ThrowIfNegative(page);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(pageSize);

        Items = items;
        Page = page;
        PageSize = pageSize;
        TotalCount = totalCount;
    }

    public IReadOnlyList<T> Items { get; }

    /// <summary>Zero-based page index.</summary>
    public int Page { get; }

    public int PageSize { get; }

    /// <summary>Total matching rows, or null when the count was deliberately skipped.</summary>
    public long? TotalCount { get; }

    /// <summary>Total pages, or null when <see cref="TotalCount"/> is null.</summary>
    public long? TotalPages =>
        TotalCount is null ? null : (long)Math.Ceiling(TotalCount.Value / (double)PageSize);

    /// <summary>
    /// True when another page is likely to exist. When the total is unknown this is
    /// inferred from a full page, which may produce one empty final page - an acceptable
    /// trade for not running an expensive COUNT.
    /// </summary>
    public bool HasMore =>
        TotalCount is null ? Items.Count == PageSize : (Page + 1L) * PageSize < TotalCount.Value;

    public static PagedResult<T> Empty(int pageSize = 50) => new([], 0, pageSize, 0);
}

/// <summary>Base for paged query requests, with clamping so a caller cannot request 100 000 rows.</summary>
public abstract record PagedRequest
{
    public const int MaxPageSize = 500;
    public const int DefaultPageSize = 50;

    private readonly int _pageSize = DefaultPageSize;
    private readonly int _page;

    /// <summary>Zero-based page index. Negative values are clamped to zero.</summary>
    public int Page
    {
        get => _page;
        init => _page = Math.Max(0, value);
    }

    /// <summary>
    /// Rows per page, clamped to <see cref="MaxPageSize"/>. Clamping rather than rejecting
    /// keeps an over-eager client working while still bounding the query.
    /// </summary>
    public int PageSize
    {
        get => _pageSize;
        init => _pageSize = value <= 0 ? DefaultPageSize : Math.Min(value, MaxPageSize);
    }

    /// <summary>Rows to skip.</summary>
    public int Skip => Page * PageSize;

    /// <summary>Whether the caller needs an exact total.</summary>
    public bool IncludeTotalCount { get; init; } = true;
}
