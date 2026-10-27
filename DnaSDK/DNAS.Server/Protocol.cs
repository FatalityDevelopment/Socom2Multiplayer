using System;
using System.Security.Cryptography;

namespace DNAS;

/// <summary>
/// Four captured encrypted proofs, in the original PS2 wire order: A40, B56,
/// serial-producing D40, disc-producing C32. Their encrypted contents are not
/// plain serial/ID bytes. Production algorithms are still under investigation.
/// </summary>

public static class Protocol
{
    private static readonly byte[] K2 = Convert.FromHexString("F297DCF807F7FEF8");
    private static readonly byte[] K2Input = Convert.FromHexString("27DCA0BD201BCD63BF63059931633854");
    private static readonly byte[] K4 = Convert.FromHexString("CD862C0297372AEF");
    private static readonly byte[] K4Input = Convert.FromHexString("C896CCDA1D89FC650098A2B0D7AEDF8E");
    private static readonly byte[] EnvelopeKey = Convert.FromHexString("EB711416CB0AB016AE190174B5CE63397B01B91880145E34");
    private static readonly byte[] EnvelopeIV = Convert.FromHexString("C510A6400A9B022F");
    private const ulong LcgMultiplier = 0x5851F42D4C957F2DUL;

    /// <summary>Advances the recorded unsigned 64-bit PS2 pseudorandom recurrence.</summary>
    public static byte[] LcgBytes(ref ulong state, int count)
    {
        if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
        byte[] output = new byte[count];
        for (int i = 0; i < count; i++)
        {
            state = unchecked(state * LcgMultiplier + 1);
            output[i] = (byte)((state >> 55) & 0xFF);
        }
        return output;
    }

    private static (byte[] k3, byte[] iv3, byte[] k5, byte[] iv5) TailKeys()
    {
        byte[] stage3 = DES.Encrypt(K2Input, K2);
        byte[] stage5 = DES.Encrypt(K4Input, K4);
        return (DES.WithOddParity(stage3.AsSpan(0, 8).ToArray()), stage3.AsSpan(8, 8).ToArray(), DES.WithOddParity(stage5.AsSpan(0, 8).ToArray()), stage5.AsSpan(8, 8).ToArray());
    }

    public static byte[] WrapInitial(InitialFields fields, byte[] random16, byte[]? fixedTrailer8 = null)
    {
        if (fields == null) throw new ArgumentNullException(nameof(fields));
        Guard.Size(random16, 16, nameof(random16));
        fixedTrailer8 ??= Public.FixedTrailer8;
        Guard.Size(fixedTrailer8, 8, nameof(fixedTrailer8));
        byte[] buf = new byte[256];
        Buffer.BlockCopy(fields.Join(), 0, buf, 0, 168);
        Buffer.BlockCopy(random16, 0, buf, 232, 16);
        Buffer.BlockCopy(fixedTrailer8, 0, buf, 248, 8);
        byte[] stage1 = DES.Encrypt(buf.AsSpan(0, 232).ToArray(), DES.WithOddParity(random16.AsSpan(0, 8).ToArray()), random16.AsSpan(8, 8).ToArray());
        Buffer.BlockCopy(stage1, 0, buf, 0, 232);
        var (k3, iv3, k5, iv5) = TailKeys();
        byte[] stage3 = DES.Encrypt(buf.AsSpan(232, 16).ToArray(), k3, iv3);
        Buffer.BlockCopy(stage3, 0, buf, 232, 16);
        byte[] stage5 = DES.Encrypt(buf.AsSpan(232, 24).ToArray(), k5, iv5);
        Buffer.BlockCopy(stage5, 0, buf, 232, 24);
        return buf;
    }

    public static UnwrappedInitial UnwrapInitial(byte[] encrypted256)
    {
        Guard.Size(encrypted256, 256, nameof(encrypted256));
        byte[] buf = (byte[])encrypted256.Clone();
        var (k3, iv3, k5, iv5) = TailKeys();
        byte[] stage5 = DES.Decrypt(buf.AsSpan(232, 24).ToArray(), k5, iv5);
        Buffer.BlockCopy(stage5, 0, buf, 232, 24);
        byte[] stage3 = DES.Decrypt(buf.AsSpan(232, 16).ToArray(), k3, iv3);
        Buffer.BlockCopy(stage3, 0, buf, 232, 16);
        byte[] random16 = buf.AsSpan(232, 16).ToArray();
        byte[] stage1 = DES.Decrypt(buf.AsSpan(0, 232).ToArray(), DES.WithOddParity(random16.AsSpan(0, 8).ToArray()), random16.AsSpan(8, 8).ToArray());
        Buffer.BlockCopy(stage1, 0, buf, 0, 232);
        bool zeroValid = true;
        for (int i = 168; i < 232; i++) if (buf[i] != 0) zeroValid = false;
        bool trailerValid = buf.AsSpan(248, 8).SequenceEqual(Public.FixedTrailer8);
        return new UnwrappedInitial(new InitialFields(buf.AsSpan(0, 40).ToArray(), buf.AsSpan(40, 56).ToArray(), buf.AsSpan(96, 40).ToArray(), buf.AsSpan(136, 32).ToArray()), random16, buf, zeroValid, trailerValid);
    }

    public static Packet BuildInitialPacket(byte[] header40, byte[] lookupId8, InitialFields fields, byte[] random16)
    {
        Guard.Size(lookupId8, 8, nameof(lookupId8));
        byte[] payload = new byte[268];
        payload[1] = 2;
        payload[3] = 5;
        Buffer.BlockCopy(lookupId8, 0, payload, 4, 8);
        Buffer.BlockCopy(WrapInitial(fields, random16), 0, payload, 12, 256);
        return Packet.Make(header40, Public.ClientConnect, payload);
    }

    public static UnwrappedInitial InspectInitialPacket(Packet initial)
    {
        Guard.Operation(initial, Public.ClientConnect, 268);
        if (!initial.Payload.AsSpan(0, 4).SequenceEqual(new byte[] { 0, 2, 0, 5 }))
            throw new FormatException("Unexpected initial request parameter.");
        return UnwrapInitial(initial.Raw.AsSpan(0x34, 256).ToArray());
    }

    public static (byte[] key24, byte[] iv8) RequestBoundKeys(Packet initial)
    {
        Guard.Operation(initial, Public.ClientConnect, 268);
        byte[] a = SHA1.HashData(initial.Raw.AsSpan(0x34, 0x100));
        byte[] b = SHA1.HashData(initial.Raw.AsSpan(0x48, 0xEC));
        byte[] material = new byte[32];
        Buffer.BlockCopy(b, 0, material, 0, 20);
        Buffer.BlockCopy(a, 0, material, 20, 12);
        return (material.AsSpan(0, 24).ToArray(), material.AsSpan(24, 8).ToArray());
    }

    public static Packet EncryptReply1(Packet initial, Packet replyPlaintext)
    {
        Guard.Operation(replyPlaintext, Public.ServerConnect, 288);
        var (key, iv) = RequestBoundKeys(initial);
        byte[] body = (byte[])replyPlaintext.Payload.Clone();
        Buffer.BlockCopy(DES.Encrypt3(body.AsSpan(160, 32).ToArray(), key, iv), 0, body, 160, 32);
        byte[] outer = DES.Encrypt3(body, EnvelopeKey, EnvelopeIV);
        return Packet.Make(replyPlaintext.Header, Public.ServerConnect, outer);
    }

    public static Packet DecryptReply1Outer(Packet reply)
    {
        Guard.Operation(reply, Public.ServerConnect, 288);
        return Packet.Make(reply.Header, Public.ServerConnect, DES.Decrypt3(reply.Payload, EnvelopeKey, EnvelopeIV));
    }

    public static Packet DecryptReply1(Packet initial, Packet reply)
    {
        Packet outer = DecryptReply1Outer(reply);
        var (key, iv) = RequestBoundKeys(initial);
        byte[] body = (byte[])outer.Payload.Clone();
        Buffer.BlockCopy(DES.Decrypt3(body.AsSpan(160, 32).ToArray(), key, iv), 0, body, 160, 32);
        return Packet.Make(outer.Header, Public.ServerConnect, body);
    }

    public static byte[] FirstReplyPrefix(Packet outerDecryptedReply, byte[] rawKey8)
    {
        Guard.Operation(outerDecryptedReply, Public.ServerConnect, 288);
        Guard.Size(rawKey8, 8, nameof(rawKey8));
        return DES.Decrypt(outerDecryptedReply.Raw.AsSpan(0x30, 16).ToArray(), DES.WithOddParity(rawKey8));
    }

    public static Packet BuildSecondRequest(byte[] header40, Packet outerDecryptedReply, byte[] rawKey8, byte[] rsaModulus128)
    {
        Guard.Operation(outerDecryptedReply, Public.ServerConnect, 288);
        byte[] prefix = FirstReplyPrefix(outerDecryptedReply, rawKey8);
        byte[] unpadded = RSA.VerifyServerOperand(outerDecryptedReply.Raw.AsSpan(0x48, 128).ToArray(), rsaModulus128);
        byte[] payload = new byte[144];
        Buffer.BlockCopy(prefix, 0, payload, 0, 16);
        Buffer.BlockCopy(unpadded, 0, payload, 16, 117);
        return Packet.Make(header40, Public.ClientProof, payload);
    }

    public static byte[] InspectSecondReply(Packet secondReply)
    {
        Guard.Operation(secondReply, Public.ServerProof, 130);
        if (secondReply.Payload[0] != 2 || secondReply.Payload[1] != 1) throw new FormatException("Expected 02 01 prefix.");
        return secondReply.Payload.AsSpan(2, 128).ToArray();
    }

    public static Packet BuildFinalRequest(byte[] header40, byte[] payload4)
    {
        Guard.Size(payload4, 4, nameof(payload4));
        return Packet.Make(header40, Public.ClientFinal, payload4);
    }

    public static (byte flag, byte[] result32) InspectFinalReply(Packet reply)
    {
        Guard.Operation(reply, Public.ServerFinal, 37);
        if (!reply.Payload.AsSpan(1, 4).SequenceEqual(new byte[] { 0, 0, 0, 32 }))
            throw new FormatException("Final response length marker mismatch.");
        if (reply.Payload[0] > 1) throw new FormatException("Unexpected original DNAS final-result flag; observed wire values are 0 or 1.");
        return (reply.Payload[0], reply.Payload.AsSpan(5, 32).ToArray());
    }
}
