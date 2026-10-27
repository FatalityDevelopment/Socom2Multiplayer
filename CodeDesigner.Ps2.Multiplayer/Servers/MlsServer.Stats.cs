using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using CodeDesigner.Ps2.Multiplayer.Storage;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>Public, read-only server statistics (served as JSON by <see cref="PatchHttpServer"/> at /stats).</summary>
public sealed record ServerStats(
    string Universe, string Description, DateTime UpdatedUtc,
    int PlayersOnline, int PlayersInRooms, int PlayersInGames, int PlayersInCommunity, int Games,
    List<RoomStats> Rooms);

public sealed record RoomStats(int Id, string Name, int Players, int MaxPlayers, int PlayersInGames, List<GameStats> Games);

public sealed record GameStats(string Name, int Players, int MaxPlayers, bool Locked);

public partial class MlsServer
{
    /// <summary>
    /// Counts only: players per briefing room (the same count the game shows), the live games listed in each and
    /// the universe totals. No account names, addresses or anything else a visitor shouldn't see.
    /// </summary>
    public ServerStats PublicStats()
    {
        var rooms = DebugRooms();
        var online = _presence.Snapshot();
        static bool InGame(PresenceRegistry.Presence p) => p.Status == MediusPlayerStatus.MediusPlayerInGameWorld;

        var roomStats = rooms.Select(room =>
        {
            var players = online.Where(p => p.State.LobbyWorldId == room.ChannelId).ToList();
            var games = _store.GetGames(room.AppId)
                .Where(g => g.LobbyChannelId == room.ChannelId
                    && g.DmeWorldId is int wid && DmeWorld.GetById(wid) is { } w && w.MediusWorldId == g.GameId)
                .Select(g => new GameStats(g.GameName, DmeWorld.GetById(g.DmeWorldId!.Value)?.ConnectedCount ?? g.PlayerCount, g.MaxPlayers, g.IsLocked))
                .ToList();
            foreach (var kv in _defaultGameWorlds.Where(kv => kv.Key >> 8 == room.ChannelId
                         && DmeWorld.GetById(kv.Value.WorldId) == kv.Value && kv.Value.ConnectedCount > 0))
            {
                int index = (kv.Key & 0xFF) - 2;
                string name = index >= 0 && index < _config.DefaultGames.Count ? _config.DefaultGames[index].Name : "Default game";
                games.Add(new GameStats(name, kv.Value.ConnectedCount, DefaultGameMaxPlayers, false));
            }
            return new RoomStats(room.ChannelId, room.ChannelName, players.Count, room.MaxPlayers,
                players.Count(p => InGame(p.State)), games.OrderByDescending(g => g.Players).ToList());
        }).ToList();

        int inRooms = roomStats.Sum(r => r.Players);
        return new ServerStats(
            _config.UniverseName, _config.UniverseDescription, DateTime.UtcNow,
            PlayersOnline: online.Count,
            PlayersInRooms: inRooms,
            PlayersInGames: online.Count(p => InGame(p.State)),
            PlayersInCommunity: online.Count - inRooms,
            Games: roomStats.Sum(r => r.Games.Count),
            Rooms: roomStats);
    }
}
