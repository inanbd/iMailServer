using System.Runtime.CompilerServices;

// The persistence machinery - AmbientDbSession, DbSession, TransactionManager, the Dapper
// repositories, the migration runner - is internal because it is implementation detail
// behind the Application layer's ports. Nothing outside this assembly should construct one.
//
// The persistence test assembly is the exception, and for a specific reason: these types are
// exactly what must be tested against a REAL database. Testing them only through the DI
// container would mean testing the container, and testing them through a fake database would
// prove nothing about SQLite's locking model or SQL Server's transient error numbers - the
// two things this layer exists to get right.
[assembly: InternalsVisibleTo("MailServer.Persistence.Tests")]
[assembly: InternalsVisibleTo("MailServer.Infrastructure.Tests")]
