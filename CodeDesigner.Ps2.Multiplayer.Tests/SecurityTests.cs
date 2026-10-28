using System.Security.Cryptography;
using System.Text;
using CodeDesigner.Ps2.Multiplayer.Servers;
using CodeDesigner.Ps2.Multiplayer.Storage;

namespace CodeDesigner.Ps2.Multiplayer.Tests;

public class PasswordHasherTests
{
    [Fact]
    public void Hash_VerifiesAndIsSalted()
    {
        var a = PasswordHasher.Hash("hunter2");
        var b = PasswordHasher.Hash("hunter2");

        Assert.NotEqual(a, b);
        Assert.True(PasswordHasher.Verify("hunter2", a, out bool upgrade));
        Assert.False(upgrade);
        Assert.False(PasswordHasher.Verify("hunter3", a, out _));
    }

    [Fact]
    public void LegacySha1_VerifiesAndAsksForUpgrade()
    {
        var legacy = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes("pw"))).ToLowerInvariant();
        Assert.True(PasswordHasher.Verify("pw", legacy, out bool upgrade));
        Assert.True(upgrade);
        Assert.False(PasswordHasher.Verify("nope", legacy, out _));
    }

    [Fact]
    public void EmptyStoredHash_NeverMatches()
    {
        Assert.False(PasswordHasher.Verify("", "", out _));
        Assert.False(PasswordHasher.Verify("anything", "", out _));
    }
}

public class AccountStoreTests
{
    [Fact]
    public async Task ConcurrentCreate_MakesOneAccount()
    {
        var store = new InMemoryStorage();
        var results = await Task.WhenAll(Enumerable.Range(0, 32)
            .Select(_ => Task.Run(() => store.TryCreateAccount("Racer", "h"))));

        Assert.Single(results, r => r != null);
        Assert.Single(store.Accounts);
    }

    [Fact]
    public void FreshLogin_ReplacesOlderSessionKeys()
    {
        var store = new InMemoryStorage();
        var a = store.TryCreateAccount("A", "h")!;

        store.RegisterSession("OLD", a.AccountId, replaceOthers: true);
        store.RegisterSession("NEW", a.AccountId, replaceOthers: true);

        Assert.Null(store.GetAccountBySession("OLD"));
        Assert.Same(a, store.GetAccountBySession("NEW"));

        store.RevokeSession("NEW");
        Assert.Null(store.GetAccountBySession("NEW"));
    }
}

public class DnsParseTests
{
    private static byte[] Query(params byte[] qname)
    {
        var header = new byte[12];
        return [.. header, .. qname, 0, 1, 0, 1];
    }

    [Fact]
    public void ParsesNormalName()
    {
        var q = Query(4, (byte)'g', (byte)'a', (byte)'t', (byte)'e', 3, (byte)'o', (byte)'r', (byte)'g', 0);
        Assert.Equal("gate.org", DnsServer.ParseQName(q, 12, out int after));
        Assert.Equal(12 + 10, after);
    }

    [Theory]
    [InlineData(new byte[] { 0xC0, 0x0C })]                 // compression pointer
    [InlineData(new byte[] { 0x40, 1, 2, 3 })]              // reserved label type
    [InlineData(new byte[] { 3, (byte)'a', (byte)'.', (byte)'b', 0 })]   // dot inside a label
    [InlineData(new byte[] { 2, (byte)'a', 0x0A, 0 })]      // control byte
    [InlineData(new byte[] { 5, (byte)'a' })]               // truncated
    public void RejectsMalformedNames(byte[] qname)
    {
        Assert.Null(DnsServer.ParseQName(Query(qname), 12, out _));
    }
}
