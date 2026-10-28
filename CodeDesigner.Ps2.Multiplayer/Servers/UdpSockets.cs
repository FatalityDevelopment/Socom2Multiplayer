using System.Net.Sockets;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

internal static class UdpSockets
{
    /// <summary>Windows SIO_UDP_CONNRESET.</summary>
    private const int SioUdpConnReset = unchecked((int)0x9800000C);

    /// <summary>
    /// On Windows an ICMP port-unreachable for an earlier reply makes the next ReceiveAsync throw ConnectionReset
    /// (10054). A spoofed source can trigger that on every packet, so turn the behaviour off.
    /// </summary>
    public static void IgnoreConnectionResets(UdpClient udp)
    {
        if (!OperatingSystem.IsWindows()) return;
        try { udp.Client.IOControl(SioUdpConnReset, [0, 0, 0, 0], null); }
        catch (SocketException) { /* not supported here: keep the default */ }
    }
}
