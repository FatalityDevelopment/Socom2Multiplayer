using CodeDesigner.Ps2.Multiplayer.Protocol;

namespace CodeDesigner.Ps2.Multiplayer.Tests;

public class ScertPacketTests
{
    [Fact]
    public void PlainPacket_RoundTrips()
    {
        var p = ScertPacket.CreateServerApp([1, 2, 3, 4]);
        var bytes = p.Serialize();

        var back = ScertPacket.TryRead(bytes, 0, bytes.Length, out int consumed);
        Assert.NotNull(back);
        Assert.Equal(bytes.Length, consumed);
        Assert.Equal(RT_MSG_TYPE.RT_MSG_SERVER_APP, back!.MessageType);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, back.Payload);
    }

    [Fact]
    public void EncryptedPacket_RoundTripsHash()
    {
        var p = new ScertPacket { MessageType = RT_MSG_TYPE.RT_MSG_SERVER_APP, Payload = [9, 9], Hash = [1, 2, 3, 4] };
        var bytes = p.Serialize();

        var back = ScertPacket.TryRead(bytes, 0, bytes.Length, out _);
        Assert.True(back!.IsEncrypted);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, back.Hash);
    }

    [Fact]
    public void PartialPacket_WaitsForMoreBytes()
    {
        var bytes = ScertPacket.CreateServerApp([1, 2, 3, 4]).Serialize();
        Assert.Null(ScertPacket.TryRead(bytes, 0, bytes.Length - 1, out int consumed));
        Assert.Equal(0, consumed);
    }

    [Fact]
    public void EncryptedEmptyFrame_HasNoHash()
    {
        byte[] bytes = [0x8F, 0x00, 0x00, 0x01, 0x00, 0x00];
        var p = ScertPacket.TryRead(bytes, 0, bytes.Length, out int consumed);
        Assert.Equal(3, consumed);
        Assert.False(p!.IsEncrypted);
    }

    [Fact]
    public void Serialize_RejectsPayloadOverLengthField()
    {
        var p = ScertPacket.CreateServerApp(new byte[ScertPacket.MaxPayloadLength + 1]);
        Assert.Throws<InvalidOperationException>(() => p.Serialize());
    }
}
