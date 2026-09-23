# POP3

RFC 1939, with RFC 2449's `CAPA` and RFC 2595's `STLS`. **Both listeners are disabled by
default.** POP3 is here for devices that cannot speak IMAP, not as an alternative to it.

That default is a recommendation as much as a safety measure. RFC 1939 §8 describes what a
maildrop becomes when clients use it as a repository — "there has been a tendency for
already-read messages to accumulate on the server without bound" — and §5's positional numbering
makes a maildrop of thousands of messages expensive to open. A mailbox served over both protocols
has a second problem: POP3's destructive read removes mail an IMAP client can still see.

Port 995 is the one to enable. RFC 8314 §3.1: "When a TCP connection is established for the
"pop3s" service (default port 995), a TLS handshake begins immediately." There is no cleartext
phase for a stripping attacker to interfere with. Port 110 exists for clients that cannot do
that, and it refuses `USER` and `PASS` until `STLS` has run.

## Authentication

**Enabling the listeners is not enough: each mailbox needs its own POP3 access.** A new mailbox is
created with IMAP and submission access and without POP3, so turning on port 995 exposes no
mailbox until an operator grants POP3 to the ones that need it — which is the point, since POP3's
destructive read is the one way a client can remove mail the others still expect. IMAP and
submission are checked the same way against their own flags. (Until the end-to-end testing after
Milestone 12, every protocol was checked against the submission flag and the POP3 flag was never
read; a mailbox that could submit could also read and delete its mail here.)

**`USER` and `PASS` are refused until TLS is active, and the `USER` capability is withheld to say
so.** RFC 2449 §6.2 makes that capability mean "that the USER and PASS commands are supported",
so not announcing it is the only vocabulary POP3 has for IMAP's `LOGINDISABLED` — RFC 2595 gives
POP3 no equivalent capability name. The command itself refuses as well, so a client that ignores
the listing gains nothing, and the refusal names the remedy: a client told only `-ERR` would show
its user a password error for what is actually a policy.

**Every refusal reads the same.** §7 permits a positive `USER` response "even though no such
mailbox exists", and this server takes that permission: an unknown address and a wrong password
are one answer, because any difference between them is an address oracle. Address enumeration is
the first step of every credential-stuffing run against a mail server.

**The whole `PASS` argument is the password, spaces included.** §7: "Since the PASS command has
exactly one argument, a POP3 server may treat spaces in the argument as part of the password,
instead of as argument separators." A server that split on spaces would refuse every passphrase,
and the user would see nothing but a wrong-password error.

**`APOP` is refused by name.** Its digest is `MD5(timestamp + shared-secret)`, which a server can
only compute if it holds the secret; this server stores password verifiers it cannot reverse, so
APOP is not declined but impossible. RFC 2449 §6 explains the rest: "there is no APOP capability
[…] Clients discover server support of APOP by the presence in the greeting banner of an initial
challenge enclosed in angle brackets." The greeting therefore never contains an angle bracket —
`Pop3Responses.Greeting` strips them out of the product name, so an operator cannot accidentally
advertise a mechanism the server cannot perform.

**A connection is not an unbounded retry budget.** §3 permits closing after a refusal — "After
returning a negative status indicator, the server may close the connection" — and this server
does so once the session's attempt limit is reached.

## The maildrop

**The maildrop is the mailbox's INBOX and only its INBOX.** RFC 1939 has no concept of a folder;
§4 speaks of "the appropriate maildrop", singular. Serving a different folder, or several, would
be inventing a protocol.

**The numbering is a snapshot taken once, at login.** §4: "After the POP3 server has opened the
maildrop, it assigns a message-number to each message, and notes the size of each message in
octets." The numbers are positions, so they cannot be recomputed mid-session without every number
the client holds changing underneath it — and POP3 has no response that could tell a client so.

**`UIDL` is the folder's UIDVALIDITY and UID, joined by a full stop.** §7 requires a unique-id "of
one to 70 characters in the range 0x21 to 0x7E, which uniquely identifies a message within a
maildrop and which persists across sessions", and adds that "the server should never reuse an
unique-id". RFC 3501 §2.3.1.1 already gives that pair exactly those properties: it "MUST NOT refer
to any other message in the mailbox or any subsequent mailbox with the same name forever". The one
case where a UID is reused — a folder deleted and recreated — is the case that gets a new
UIDVALIDITY. Nothing is stored for POP3 that IMAP was not already storing.

**Known limitation: the exclusive-access lock is process-local.** §4 requires one, "as necessary
to prevent messages from being modified or removed before the session enters the UPDATE state",
and a second session for the same mailbox is refused with RFC 2449 §8.1.2's `-ERR [IN-USE]`. The
lock is held in memory by one server process, so two processes serving one database would each
grant it. Making it durable would mean a row that outlives a crashed session and a timeout to
release it, and a lock that can be held by a process that no longer exists is worse than one that
is only as strong as the deployment. The single-process deployment this server is built for is
the case it is correct in.

## Deletion

**A `DELE` marks; only a `QUIT` from TRANSACTION removes.** §5: "The POP3 server does not actually
delete the message until the POP3 session enters the UPDATE state." §6 makes the other half a
MUST: "If a session terminates for some reason other than a client-issued QUIT command, the POP3
session does NOT enter the UPDATE state and MUST not remove any messages from the maildrop."

The marks therefore live in the session's own memory and nowhere else. Marking in the database
instead would leave a dropped connection's marks behind — and these mailboxes are also reachable
over IMAP, where a stray `\Deleted` shows the user mail they never deleted. The state machine
enforces it structurally: `EnterUpdate` is the only path to the state that removes anything, and
it throws from anywhere but TRANSACTION.

**The removal names its messages.** It deliberately does not reuse IMAP's `EXPUNGE`, which removes
every message in the folder carrying `\Deleted` — including ones an IMAP client marked and has
deliberately not expunged. That is mail the user did not ask anybody to destroy.

**The lock is released whether or not the removal worked**, per §6, and on every exit path rather
than only the tidy one: a maildrop left locked by a dropped connection would refuse the user's
next attempt until the process restarted.

## Framing

**Byte-stuffing is the single most dangerous piece of POP3 to get wrong.** §3: "If any line of the
multi-line response begins with the termination octet, the line is "byte-stuffed" by pre-pending
the termination octet to that line of the response." A body line beginning with a full stop is
ordinary — a wrapped sentence, a signature, a quoted diff — and a server that failed to stuff one
would end the response there, hand the rest of the message to the client as if it were protocol,
and desynchronise the connection for good. In the other direction a client removes one leading
stop from every line, so stuffing a line that did not need it corrupts the message silently.

The stuffing and the terminator are produced together, so no call site can perform one without the
other. Bare line feeds start a line as CRLF does, because a message written by local delivery may
use them and a scan that knew only CRLF would leave such a line unstuffed. A body whose last line
was never terminated gets a line ending before the terminator — otherwise the client reads the
stop as part of the message and waits for an end that never comes.

**The autologout is silent.** §3: "When the timer expires, the session does NOT enter the UPDATE
state--the server should close the TCP connection without removing any messages or sending any
response to the client." Unlike IMAP, which has an untagged `BYE` for this, POP3 asks for no
response at all.

**`PIPELINING` is advertised and honoured.** RFC 2449 §6.6 requires that a server which announces
it "MUST process each command in turn", which this server does: commands are read one at a time
from a buffered reader and each is answered before the next is read. The one place it is not true
is across an `STLS` upgrade, where the buffer is discarded — and RFC 2595 §4 forbids a client from
pipelining there.

## Known limitations

**A message is read whole into memory to be sent.** The stuffing has to be applied before the
first octet goes out, so a stream would have to be transformed on the way in any case. That is per
message rather than per session, but a `RETR` of a very large message holds it.

**`LIST` and `STAT` report the stored size, and a message with no final line ending is sent two
octets longer.** §11 anticipates the general problem — "the octet count for a message on the
server host may differ from the octet count assigned to that message due to local conventions for
designating end-of-line" — and the specific case here is the line ending the framing adds before
the terminator. Computing the true transmitted size would mean reading every message to answer a
`LIST`, which is exactly the cost §8 warns about.

**`AUTH` (RFC 1734 / RFC 5034) is not implemented.** `USER` and `PASS` over TLS satisfy §4's
requirement that "a POP3 server must of course support at least one authentication mechanism", and
the legacy devices this listener exists for use them. The `SASL` capability is therefore not
announced, which RFC 2449 §6.3 makes the correct pairing.
