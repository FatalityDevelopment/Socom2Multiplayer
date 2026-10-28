using CodeDesigner.Ps2.Multiplayer.Protocol;
using CodeDesigner.Ps2.Multiplayer.Servers;

namespace CodeDesigner.Ps2.Multiplayer.Tests;

public class WireFixTests
{
    [Fact]
    public void NetConnectionInfo_Is156BytesUnlessTrimmed()
    {
        static int Size()
        {
            var w = new MediusWriter();
            w.WriteNetConnectionInfo(NetConnectionType.ClientServerTCP, null, null, 1, null, "S", "A");
            return w.ToArray().Length;
        }

        Assert.Equal(156, Size());   // the hardware-tested default
        MediusWriterExtensions.Trim154 = true;
        try { Assert.Equal(154, Size()); }
        finally { MediusWriterExtensions.Trim154 = false; }
    }

    [Fact]
    public void EmptyGameListRow_HasEndOfListWhereARealRowDoes()
    {
        var request = MediusPacket.BuildLobby(MediusLobbyMessageId.GameList_ExtraInfo0, new byte[23]);
        var w = new MediusWriter();
        MlsServer.WriteEmptyGameListRow(w, request);
        var row = w.ToArray();

        Assert.Equal(0x190, row.Length);
        Assert.Equal(1, row[0x18C]);
        Assert.Equal((int)MediusCallbackStatus.MediusNoResult, BitConverter.ToInt32(row, 0x18));
    }
}
