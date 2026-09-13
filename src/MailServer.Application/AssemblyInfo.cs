using System.Runtime.CompilerServices;

// Handlers are internal: they are an implementation detail of the Application layer, invoked
// only through MediatR, and nothing outside this assembly should construct one directly.
//
// The test assembly is the exception. Testing a handler through the full MediatR pipeline
// would test the pipeline as much as the handler and make failures harder to localise, so
// the tests construct handlers directly. That is worth one InternalsVisibleTo; the
// alternative - making every handler public purely so tests can reach it - would widen the
// assembly's real contract for the sake of the test project.
[assembly: InternalsVisibleTo("MailServer.Application.Tests")]
