using System.Collections.Concurrent;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Smtp;

/// <summary>A held connection slot. Disposing releases it.</summary>
public interface ISmtpConnectionSlot : IDisposable
{
    /// <summary>The address the slot was taken for.</summary>
    IpAddressValue RemoteAddress { get; }
}

/// <summary>Why a connection was refused.</summary>
public enum SmtpAdmission
{
    /// <summary>A slot was taken.</summary>
    Admitted = 0,

    /// <summary>The server is at its global connection limit.</summary>
    ServerBusy = 1,

    /// <summary>This address already holds its share of connections.</summary>
    AddressBusy = 2,
}

/// <summary>
/// Bounds concurrent connections, globally and per source address.
/// </summary>
/// <remarks>
/// <para>
/// Two limits because they stop different things. The global cap stops the server running out of
/// sockets, threads or memory no matter who is connecting. The per-address cap stops one peer
/// consuming the global cap on its own — which is the cheap, effective denial of service against
/// a mail server, and which the global cap alone does nothing about.
/// </para>
/// <para>
/// The per-address count is taken <b>before</b> the global one and released in the reverse order,
/// so a refusal never leaves a count raised. Getting that wrong leaks slots slowly and the
/// server stops accepting mail days later for no visible reason.
/// </para>
/// <para>Thread-safe; one instance serves every listener.</para>
/// </remarks>
public sealed class SmtpConnectionLimiter(int maxTotal, int maxPerAddress)
{
    private readonly ConcurrentDictionary<string, int> _perAddress = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    private int _total;

    /// <summary>The global cap.</summary>
    public int MaxTotal { get; } = maxTotal > 0
        ? maxTotal
        : throw new ArgumentOutOfRangeException(nameof(maxTotal));

    /// <summary>The per-address cap.</summary>
    public int MaxPerAddress { get; } = maxPerAddress > 0
        ? maxPerAddress
        : throw new ArgumentOutOfRangeException(nameof(maxPerAddress));

    /// <summary>Connections currently held.</summary>
    public int CurrentTotal
    {
        get
        {
            lock (_gate)
            {
                return _total;
            }
        }
    }

    /// <summary>Connections currently held by one address.</summary>
    public int CurrentFor(IpAddressValue address)
    {
        ArgumentNullException.ThrowIfNull(address);

        lock (_gate)
        {
            return _perAddress.GetValueOrDefault(address.Value);
        }
    }

    /// <summary>Takes a slot, or explains why it could not.</summary>
    public SmtpAdmission TryAdmit(IpAddressValue address, out ISmtpConnectionSlot? slot)
    {
        ArgumentNullException.ThrowIfNull(address);

        slot = null;

        lock (_gate)
        {
            int forAddress = _perAddress.GetValueOrDefault(address.Value);

            if (forAddress >= MaxPerAddress)
            {
                return SmtpAdmission.AddressBusy;
            }

            if (_total >= MaxTotal)
            {
                return SmtpAdmission.ServerBusy;
            }

            _perAddress[address.Value] = forAddress + 1;
            _total++;
        }

        slot = new Slot(this, address);

        return SmtpAdmission.Admitted;
    }

    private void Release(IpAddressValue address)
    {
        lock (_gate)
        {
            _total--;

            int remaining = _perAddress.GetValueOrDefault(address.Value) - 1;

            if (remaining <= 0)
            {
                // Removed rather than left at zero. A long-lived server sees a great many
                // distinct addresses, and a dictionary that only ever grows is a slow leak an
                // attacker can drive by connecting once from each of many addresses.
                _perAddress.TryRemove(address.Value, out _);
            }
            else
            {
                _perAddress[address.Value] = remaining;
            }
        }
    }

    private sealed class Slot(SmtpConnectionLimiter limiter, IpAddressValue address) : ISmtpConnectionSlot
    {
        private bool _released;

        public IpAddressValue RemoteAddress => address;

        public void Dispose()
        {
            // Idempotent. A slot released twice would decrement a count someone else is holding,
            // and the resulting under-count lets the caps be exceeded silently.
            if (_released)
            {
                return;
            }

            _released = true;
            limiter.Release(address);
        }
    }
}
