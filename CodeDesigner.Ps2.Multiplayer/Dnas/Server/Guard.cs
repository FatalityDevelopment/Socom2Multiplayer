using System;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Shared structural guards for exact-sized fields, wire opcodes and
/// session/header continuity. Cryptographic checks live in DNAS routines.
/// </summary>

internal static class Guard
{
    internal static void Size(byte[]? data, int size, string name)
    {
        if (data == null || data.Length != size) throw new ArgumentException($"{name} must contain {size} bytes.", name);
    }
    internal static void Operation(Packet p, uint operation, int payloadLength)
    {
        if (p.Operation != operation || p.Payload.Length != payloadLength)
            throw new ArgumentException($"Expected PS2 DNAS operation 0x{operation:X8} with {payloadLength} payload bytes.");
    }
    internal static void SameSession(Packet earlier, Packet later)
    {
        if (!earlier.SessionId.AsSpan().SequenceEqual(later.SessionId)) throw new FormatException("PS2 DNAS session identifier changed unexpectedly.");
        if (!earlier.Header.AsSpan(4, 23).SequenceEqual(later.Header.AsSpan(4, 23)) || earlier.Header[35] != later.Header[35])
            throw new FormatException("PS2 DNAS response changed the session metadata unexpectedly.");
    }
}
