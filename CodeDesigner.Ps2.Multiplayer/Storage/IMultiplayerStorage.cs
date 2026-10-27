using CodeDesigner.Ps2.Multiplayer.Models;

namespace CodeDesigner.Ps2.Multiplayer.Storage
{
    public interface IMultiplayerStorage
    {
        MediusAccount CreateAccount(string name, string passwordHash);
        MediusChannel CreateChannel(string name, int appId, int maxPlayers = 256);
        MediusGame CreateGame(string name, int appId, int hostAccountId, string hostName, int maxPlayers);
        MediusAccount? GetAccountById(int id);
        MediusAccount? GetAccountByName(string name);
        MediusChannel? GetChannelById(int id);
        IEnumerable<MediusChannel> GetChannels(int appId);
        MediusGame? GetGameById(int id);
        IEnumerable<MediusGame> GetGames(int appId);
        MediusChannel GetOrCreateDefaultChannel(int appId);
        MediusChannel GetOrCreateChannel(int channelId, string name, int appId, int maxPlayers = 256);
        bool RemoveGame(int gameId);
    }
}