using System.Runtime.CompilerServices;

// The dispatcher and caller-identity types are internal: they are implementation detail of
// the server side of the pipe, not part of this assembly's contract. The test assembly needs
// them because the dispatcher is where the security-relevant decisions live - protocol
// version checks, command-registry lookup, identity assignment - and those must be tested
// directly rather than inferred from the outside.
[assembly: InternalsVisibleTo("MailServer.Ipc.Tests")]
