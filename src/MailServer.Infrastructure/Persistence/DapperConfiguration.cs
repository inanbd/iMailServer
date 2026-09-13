using System.Data;
using System.Globalization;
using Dapper;

namespace MailServer.Infrastructure.Persistence;

/// <summary>
/// Global Dapper configuration, applied once before any query runs.
/// </summary>
/// <remarks>
/// <para>
/// The two supported providers represent the same logical column with different CLR types,
/// and Dapper needs to be told how to reconcile them:
/// </para>
/// <list type="bullet">
///   <item><description>SQL Server's <c>DATETIMEOFFSET</c> comes back as a real
///   <see cref="DateTimeOffset"/>.</description></item>
///   <item><description>SQLite has no date type at all. Microsoft.Data.Sqlite stores a
///   <see cref="DateTimeOffset"/> as ISO-8601 TEXT and hands it back as a
///   <see cref="string"/>.</description></item>
///   <item><description>SQL Server's <c>UNIQUEIDENTIFIER</c> comes back as a real
///   <see cref="Guid"/>; SQLite stores it as TEXT and hands back a
///   <see cref="string"/>.</description></item>
/// </list>
/// <para>
/// Without a handler, Dapper's generated deserialiser tries to cast that string straight to
/// <see cref="DateTimeOffset"/> and fails. Registering one handler here fixes every
/// timestamp column in the product at once - <c>CreatedUtc</c>, <c>TimestampUtc</c>,
/// <c>AppliedUtc</c>, and every queue and delivery timestamp still to come - rather than
/// leaving each query to discover the problem separately.
/// </para>
/// </remarks>
public static class DapperConfiguration
{
    private static readonly Lock InitializationLock = new();
    private static bool _initialized;

    /// <summary>Registers the type handlers. Idempotent and safe to call from any thread.</summary>
    public static void Initialize()
    {
        // Dapper's handler table is process-global mutable state, so registration must happen
        // exactly once. Double-checked locking rather than a static constructor, because the
        // caller decides when this runs.
        if (_initialized)
        {
            return;
        }

        lock (InitializationLock)
        {
            if (_initialized)
            {
                return;
            }

            SqlMapper.AddTypeHandler(new DateTimeOffsetHandler());
            SqlMapper.AddTypeHandler(new NullableDateTimeOffsetHandler());
            SqlMapper.AddTypeHandler(new GuidHandler());
            SqlMapper.AddTypeHandler(new NullableGuidHandler());

            _initialized = true;
        }
    }

    /// <summary>Reads a <see cref="DateTimeOffset"/> from either provider's representation.</summary>
    private sealed class DateTimeOffsetHandler : SqlMapper.TypeHandler<DateTimeOffset>
    {
        public override DateTimeOffset Parse(object value) => ParseCore(value)
            ?? throw new InvalidCastException(
                "A non-nullable DateTimeOffset column returned NULL.");

        public override void SetValue(IDbDataParameter parameter, DateTimeOffset value) =>
            SetParameter(parameter, value);

        internal static DateTimeOffset? ParseCore(object? value) => value switch
        {
            null or DBNull => null,

            DateTimeOffset dto => dto,

            // SQL Server's DATETIME2 path, and any column read as a bare DateTime.
            // Unspecified is treated as UTC because every timestamp this product writes is
            // UTC; guessing local time here would silently shift stored values by the
            // machine's offset.
            DateTime dt => dt.Kind switch
            {
                DateTimeKind.Utc => new DateTimeOffset(dt, TimeSpan.Zero),
                DateTimeKind.Local => new DateTimeOffset(dt).ToUniversalTime(),
                _ => new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc), TimeSpan.Zero),
            },

            // SQLite's representation.
            string text => DateTimeOffset.Parse(
                text,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind | DateTimeStyles.AssumeUniversal),

            _ => throw new InvalidCastException(
                $"Cannot convert {value.GetType().Name} to DateTimeOffset."),
        };

        internal static void SetParameter(IDbDataParameter parameter, DateTimeOffset? value)
        {
            // Both providers accept a DateTimeOffset parameter directly: SqlClient binds it
            // to DATETIMEOFFSET, and Microsoft.Data.Sqlite formats it as ISO-8601 TEXT. The
            // asymmetry is only on the read side.
            parameter.Value = value.HasValue ? value.Value.ToUniversalTime() : DBNull.Value;
        }
    }

    /// <summary>Nullable counterpart, for columns such as <c>ModifiedUtc</c>.</summary>
    private sealed class NullableDateTimeOffsetHandler : SqlMapper.TypeHandler<DateTimeOffset?>
    {
        public override DateTimeOffset? Parse(object value) =>
            DateTimeOffsetHandler.ParseCore(value);

        public override void SetValue(IDbDataParameter parameter, DateTimeOffset? value) =>
            DateTimeOffsetHandler.SetParameter(parameter, value);
    }

    /// <summary>Reads a <see cref="Guid"/> from either provider's representation.</summary>
    /// <remarks>
    /// Every primary key in the schema is a GUID, so without this handler nothing at all
    /// loads under SQLite. The BLOB branch exists because a database created by other tooling
    /// may have stored GUIDs as 16 raw bytes rather than as text.
    /// </remarks>
    private sealed class GuidHandler : SqlMapper.TypeHandler<Guid>
    {
        public override Guid Parse(object value) => ParseCore(value)
            ?? throw new InvalidCastException("A non-nullable Guid column returned NULL.");

        public override void SetValue(IDbDataParameter parameter, Guid value) =>
            SetParameter(parameter, value);

        internal static Guid? ParseCore(object? value) => value switch
        {
            null or DBNull => null,
            Guid guid => guid,
            string text => Guid.Parse(text),
            byte[] { Length: 16 } bytes => new Guid(bytes),
            _ => throw new InvalidCastException($"Cannot convert {value.GetType().Name} to Guid."),
        };

        internal static void SetParameter(IDbDataParameter parameter, Guid? value)
        {
            // Both providers accept a Guid parameter directly: SqlClient binds it to
            // UNIQUEIDENTIFIER, and Microsoft.Data.Sqlite writes the 36-character text form.
            // The asymmetry is only on the read side.
            parameter.Value = value.HasValue ? value.Value : (object)DBNull.Value;
        }
    }

    /// <summary>Nullable counterpart, for optional foreign keys.</summary>
    private sealed class NullableGuidHandler : SqlMapper.TypeHandler<Guid?>
    {
        public override Guid? Parse(object value) => GuidHandler.ParseCore(value);

        public override void SetValue(IDbDataParameter parameter, Guid? value) =>
            GuidHandler.SetParameter(parameter, value);
    }
}
