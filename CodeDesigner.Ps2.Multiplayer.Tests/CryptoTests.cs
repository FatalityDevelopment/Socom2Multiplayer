using System.Numerics;
using CodeDesigner.Ps2.Multiplayer.Crypto;

namespace CodeDesigner.Ps2.Multiplayer.Tests;

public class CryptoTests
{
    [Fact]
    public void Rc4_RoundTrips()
    {
        var key = PS2_RC4.GenerateKey();
        var plain = "SOCOM II multiplayer"u8.ToArray();

        PS2_RC4.Encrypt(key, CipherContext.RcServerSession, plain, out var cipher, out var hash);
        Assert.NotEqual(plain, cipher);

        PS2_RC4.Decrypt(key, hash, cipher);
        Assert.Equal(plain, cipher);
    }

    [Fact]
    public void Rc4_ZeroHashIsPlaintextPassThrough()
    {
        var data = new byte[] { 1, 2, 3 };
        PS2_RC4.Decrypt(PS2_RC4.GenerateKey(), new byte[4], data);
        Assert.Equal(new byte[] { 1, 2, 3 }, data);
    }

    [Fact]
    public void Rsa_RoundTrips()
    {
        var rsa = Ps2Rsa.GenerateKeyPair();
        var m = Ps2Rsa.GenerateMessageLessThan(rsa.N);
        Assert.Equal(m, rsa.DecryptRaw(rsa.Encrypt(m)));
    }

    [Fact]
    public void GenerateMessageLessThan_RejectsTinyModulus()
    {
        // A modulus of 0..small would make the rejection-sampling loop spin forever.
        Assert.Throws<ArgumentOutOfRangeException>(() => Ps2Rsa.GenerateMessageLessThan(BigInteger.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => Ps2Rsa.GenerateMessageLessThan(new BigInteger(12345)));
    }

    [Fact]
    public void IsUsableClientModulus_RequiresFull512BitKey()
    {
        Assert.False(Ps2Rsa.IsUsableClientModulus(Array.Empty<byte>()));
        Assert.False(Ps2Rsa.IsUsableClientModulus(new byte[64]));
        Assert.True(Ps2Rsa.IsUsableClientModulus(Ps2Rsa.GenerateKeyPair().GetPublicKey()));
    }
}
