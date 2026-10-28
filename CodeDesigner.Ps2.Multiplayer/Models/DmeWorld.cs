using System.Collections.Concurrent;
using CodeDesigner.Ps2.Multiplayer.Protocol;

namespace CodeDesigner.Ps2.Multiplayer.Models;

/// <summary>
/// A DME game world: an active session that relays RT packets between connected game clients.
///
/// Adapted from horizon-server Server.Dme/Models/World.cs, reworked to use raw
/// .NET sockets instead of DotNetty.
/// </summary>
public class DmeWorld
{
    public const int MaxClientsPerWorld = 32;

    /// <summary>
    /// World ids run 1..255: SOCOM II (v108) sends the target world in ONE byte of CLIENT_CONNECT_TCP
    /// (the high byte of the TargetWorldId u32), so a DME world id must fit in a byte. 0 is left unused.
    /// </summary>
    public const int MaxWorldId = 255;

    // ── Static world registry ─────────────────────────────────────────────────

    private static readonly ConcurrentDictionary<int, DmeWorld> _idToWorld = new();
    private static int _idCounter = 1;
    private static readonly object _idLock = new();

    public static DmeWorld? GetById(int id)
        => _idToWorld.TryGetValue(id, out var w) ? w : null;

    public static IEnumerable<DmeWorld> All => _idToWorld.Values;

    // ── Instance ──────────────────────────────────────────────────────────────

    /// <summary>DME world id (1–255) — the WorldID put in JoinGameResponse's NetConnectionInfo.</summary>
    public int WorldId { get; private set; } = -1;

    /// <summary>The Medius game (MediusWorldID as listed in the game list) this world hosts.</summary>
    public int MediusWorldId { get; }

    /// <summary>Application / game ID (AppId) this world belongs to.</summary>
    public int AppId { get; }

    /// <summary>Maximum number of players permitted in this world.</summary>
    public int MaxPlayers { get; }

    public DateTime CreatedAt { get; } = DateTime.UtcNow;

    /// <summary>Destroy the world once its last client leaves (player-created games).</summary>
    public bool SelfDestructFlag { get; set; }

    /// <summary>True once the world has been destroyed: it takes no new reservations.</summary>
    public bool IsDestroyed { get; private set; }

    /// <summary>Last time a slot was reserved or released; an empty world is swept a grace period after this.</summary>
    public DateTime LastOccupancyChangeAt { get; private set; } = DateTime.UtcNow;

    /// <summary>Slots (reserved or connected) indexed by DME client index.</summary>
    public ConcurrentDictionary<int, DmeClientState> Clients { get; } = new();

    private readonly bool[] _slotUsed = new bool[MaxClientsPerWorld];
    private readonly object _slotLock = new();

    public DmeWorld(int mediusWorldId, int appId, int maxPlayers)
    {
        MediusWorldId = mediusWorldId;
        AppId         = appId;
        MaxPlayers    = Math.Clamp(maxPlayers, 1, MaxClientsPerWorld);
        RegisterWorld();
    }

    // ── Slot management ───────────────────────────────────────────────────────

    private bool TryAllocateSlot(out int index)
    {
        lock (_slotLock)
        {
            for (index = 0; index < MaxPlayers; index++)
            {
                if (!_slotUsed[index])
                {
                    _slotUsed[index] = true;
                    return true;
                }
            }
        }
        index = -1;
        return false;
    }

    private void ReleaseSlot(int index)
    {
        if ((uint)index < (uint)MaxClientsPerWorld)
            lock (_slotLock)
                _slotUsed[index] = false;
    }

    // ── Client management ─────────────────────────────────────────────────────

    /// <summary>
    /// Reserve a slot for a player joining through MLS. Re-joining with the same session key reuses the
    /// existing slot (horizon behaviour). Returns null when the world is full.
    /// </summary>
    public DmeClientState? Reserve(string sessionKey, int accountId, bool spectator = false)
    {
        // One lock for the lookup and the allocation: two joins with the same session key must share a slot,
        // and a world being destroyed must not hand out new ones.
        lock (_slotLock)
        {
            if (IsDestroyed) return null;

            var existing = Clients.Values.FirstOrDefault(c => c.SessionKey == sessionKey && !c.Disconnected);
            if (existing != null)
            {
                existing.IsSpectator = spectator;
                return existing;
            }

            if (!TryAllocateSlot(out int index))
                return null;

            string token = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));
            var client = new DmeClientState(sessionKey, token, accountId, this, index) { IsSpectator = spectator };
            if (!Clients.TryAdd(index, client))
            {
                ReleaseSlot(index);
                return null;
            }
            LastOccupancyChangeAt = DateTime.UtcNow;
            return client;
        }
    }

    /// <summary>Find a reserved slot by the access token presented in the DME connect.</summary>
    public DmeClientState? FindByAccessKey(string accessKey)
        => Clients.Values.FirstOrDefault(c => c.AccessKey == accessKey && !c.Disconnected);

    /// <summary>
    /// Claim the reserved slot for <paramref name="accessKey"/> for connection <paramref name="connectionId"/>.
    /// Null when there is no such reservation or another connection already holds it.
    /// </summary>
    public DmeClientState? TryBind(string accessKey, string connectionId)
    {
        lock (_slotLock)
        {
            if (IsDestroyed) return null;
            var slot = FindByAccessKey(accessKey);
            if (slot == null || slot.IsConnected) return null;
            slot.IsConnected       = true;
            slot.BoundConnectionId = connectionId;
            return slot;
        }
    }

    /// <summary>Remove a client and free its slot.</summary>
    public void RemoveClient(DmeClientState client)
    {
        client.MarkDisconnected();
        lock (_slotLock)
        {
            // Only free the index if it still holds THIS client (a stale handle must not evict a newer one).
            if (Clients.TryRemove(new KeyValuePair<int, DmeClientState>(client.DmeId, client)))
                ReleaseSlot(client.DmeId);
            LastOccupancyChangeAt = DateTime.UtcNow;
        }
    }

    /// <summary>Destroy the world if nobody holds a slot in it (fake clients included). True when it was destroyed.</summary>
    public bool TryDestroyIfEmpty()
    {
        lock (_slotLock)
        {
            if (IsDestroyed) return true;
            if (!Clients.IsEmpty || _fakeIds.Count > 0) return false;
            DestroyLocked();
            return true;
        }
    }

    /// <summary>
    /// Housekeeping for every world: drop reservations nobody connected to within <paramref name="reservationTtl"/>,
    /// then destroy self-destructing worlds that have been empty for <paramref name="emptyGrace"/>. Without this a
    /// game whose host never reached the DME (or a failed join) kept its world, and its game-list row, forever —
    /// and world ids run out at 255. Returns the worlds destroyed.
    /// </summary>
    public static List<DmeWorld> Sweep(TimeSpan reservationTtl, TimeSpan emptyGrace)
    {
        var destroyed = new List<DmeWorld>();
        var now = DateTime.UtcNow;
        foreach (var world in _idToWorld.Values)
        {
            lock (world._slotLock)
            {
                foreach (var slot in world.Clients.Values)
                    if (!slot.IsConnected && now - slot.ReservedAt > reservationTtl)
                        world.RemoveClient(slot);

                if (world.SelfDestructFlag && world.Clients.IsEmpty && world._fakeIds.Count == 0
                    && DateTime.UtcNow - world.LastOccupancyChangeAt >= emptyGrace)
                {
                    world.DestroyLocked();
                    destroyed.Add(world);
                }
            }
        }
        return destroyed;
    }

    /// <summary>Forget every world (server shutdown).</summary>
    public static void DestroyAll()
    {
        foreach (var world in _idToWorld.Values)
            world.Destroy();
    }

    /// <summary>Number of clients with a live DME connection (players and spectators).</summary>
    public int ConnectedCount => Clients.Values.Count(c => c.IsConnected && !c.Disconnected);

    /// <summary>Connected clients that joined as spectators.</summary>
    public int SpectatorCount => Clients.Values.Count(c => c.IsConnected && !c.Disconnected && c.IsSpectator);

    // ── Packet relay ──────────────────────────────────────────────────────────

    /// <summary>Relay an application broadcast from <paramref name="source"/> to every other joined client.</summary>
    public void BroadcastApp(DmeClientState source, byte[] payload)
    {
        if (FakeIds.Count > 0) RecordToFake(source.DmeId, -1, payload);   // -1 = broadcast
        foreach (var (_, client) in Clients)
        {
            if (client == source || !client.HasJoined) continue;
            if (!client.HasRecvFlag(RT_RECV_FLAG.RECV_BROADCAST)) continue;
            Forward(client, source.DmeId, payload);
        }
    }

    /// <summary>Send an application packet from <paramref name="source"/> to a single target by DME id.</summary>
    public void SendAppSingle(DmeClientState source, int targetDmeId, byte[] payload)
    {
        if (IsFake(targetDmeId)) RecordToFake(source.DmeId, targetDmeId, payload);
        else if (Clients.TryGetValue(targetDmeId, out var target)
            && target.HasJoined
            && target.HasRecvFlag(RT_RECV_FLAG.RECV_SINGLE))
        {
            Forward(target, source.DmeId, payload);
        }
    }

    /// <summary>Send an application packet from <paramref name="source"/> to a list of target DME ids.</summary>
    public void SendAppList(DmeClientState source, IEnumerable<int> targetIds, byte[] payload)
    {
        foreach (var tid in targetIds)
        {
            if (IsFake(tid)) RecordToFake(source.DmeId, tid, payload);
            else if (Clients.TryGetValue(tid, out var target)
                && target.HasJoined
                && target.HasRecvFlag(RT_RECV_FLAG.RECV_LIST))
            {
                Forward(target, source.DmeId, payload);
            }
        }
    }

    // ── Fake clients (debug API) ──────────────────────────────────────────────

    private readonly HashSet<int> _fakeIds = new();

    /// <summary>Slot indexes held by debug-API fake clients (no connection behind them).</summary>
    public IReadOnlyCollection<int> FakeIds { get { lock (_slotLock) return _fakeIds.ToArray(); } }

    /// <summary>Reserve <paramref name="index"/> for a fake client, or the first free slot when null.</summary>
    public int? ReserveFake(int? index)
    {
        lock (_slotLock)
        {
            if (index is int i)
            {
                if ((uint)i >= (uint)MaxClientsPerWorld || _slotUsed[i]) return null;
                _slotUsed[i] = true;
                _fakeIds.Add(i);
                return i;
            }
            for (int n = 0; n < MaxPlayers; n++)
            {
                if (_slotUsed[n]) continue;
                _slotUsed[n] = true;
                _fakeIds.Add(n);
                return n;
            }
            return null;
        }
    }

    public bool IsFake(int index) { lock (_slotLock) return _fakeIds.Contains(index); }

    /// <summary>App payloads real clients addressed to fake clients (newest last, capped).</summary>
    public ConcurrentQueue<(DateTime At, int From, int To, byte[] Payload)> FakeInbox { get; } = new();

    private void RecordToFake(int from, int to, byte[] payload)
    {
        FakeInbox.Enqueue((DateTime.UtcNow, from, to, payload));
        while (FakeInbox.Count > 500) FakeInbox.TryDequeue(out _);
    }

    public bool ReleaseFake(int index)
    {
        lock (_slotLock)
        {
            if (!_fakeIds.Remove(index)) return false;
            LastOccupancyChangeAt = DateTime.UtcNow;
            _slotUsed[index] = false;
            return true;
        }
    }

    /// <summary>Send one RT frame to every joined real client, bypassing the notification gate.</summary>
    public int SendToJoined(RT_MSG_TYPE type, byte[] payload)
    {
        int sent = 0;
        foreach (var (_, client) in Clients)
        {
            if (!client.HasJoined || client.Disconnected) continue;
            client.Send(type, payload);
            sent++;
        }
        return sent;
    }

    /// <summary>Relay an application payload to every joined real client as if <paramref name="sourceDmeId"/> sent it.</summary>
    public int ForwardAppFrom(int sourceDmeId, byte[] payload)
    {
        int sent = 0;
        foreach (var (_, client) in Clients)
        {
            if (!client.HasJoined || client.Disconnected || client.DmeId == sourceDmeId) continue;
            Forward(client, sourceDmeId, payload);
            sent++;
        }
        return sent;
    }

    public void NotifyPlayerJoined(DmeClientState joined)
    {
        foreach (var (_, client) in Clients)
        {
            if (client == joined || !client.HasJoined) continue;
            if (!client.HasRecvFlag(RT_RECV_FLAG.RECV_NOTIFICATION)) continue;
            client.SendConnectNotify(joined);
        }
    }

    public void NotifyPlayerLeft(DmeClientState left)
    {
        foreach (var (_, client) in Clients)
        {
            if (client == left || !client.HasJoined) continue;
            if (!client.HasRecvFlag(RT_RECV_FLAG.RECV_NOTIFICATION)) continue;
            client.SendDisconnectNotify(left);
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void Destroy()
    {
        lock (_slotLock) DestroyLocked();
    }

    private void DestroyLocked()
    {
        IsDestroyed = true;
        _idToWorld.TryRemove(new KeyValuePair<int, DmeWorld>(WorldId, this));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Server→client relay frame: RT_MSG_CLIENT_APP_SINGLE [sourceDmeId:2 LE][payload] (horizon
    /// TargetOrSource convention; retail DME traffic to the client is CLIENT_APP_SINGLE frames).
    /// </summary>
    private static void Forward(DmeClientState target, int sourceDmeId, byte[] payload)
    {
        // The 2-byte source prefix must still fit the frame's 16-bit length.
        if (payload.Length + 2 > ScertPacket.MaxPayloadLength) return;
        var body = new byte[2 + payload.Length];
        body[0] = (byte)sourceDmeId;
        body[1] = (byte)(sourceDmeId >> 8);
        Buffer.BlockCopy(payload, 0, body, 2, payload.Length);
        target.Send(RT_MSG_TYPE.RT_MSG_CLIENT_APP_SINGLE, body);
    }

    private void RegisterWorld()
    {
        lock (_idLock)
        {
            for (int tried = 0; tried < MaxWorldId; tried++)
            {
                int id = _idCounter;
                _idCounter = _idCounter >= MaxWorldId ? 1 : _idCounter + 1;
                if (_idToWorld.TryAdd(id, this))
                {
                    WorldId = id;
                    return;
                }
            }
            throw new InvalidOperationException("Maximum DME worlds reached.");
        }
    }

    public override string ToString()
        => $"DmeWorld(id={WorldId}, game=0x{MediusWorldId:X}, clients={ConnectedCount}/{MaxPlayers}" +
           (SpectatorCount > 0 ? $", spectators={SpectatorCount})" : ")");
}
