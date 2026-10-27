using System.Text;
using CodeDesigner.Ps2.Multiplayer.Crypto;

namespace CodeDesigner.Ps2.Multiplayer.Protocol;

/// <summary>
/// Decodes raw Ethernet frames into a Wireshark-style layer tree, with
/// field-level decoding of the SCERT / Medius application protocols.
///
/// This is the canonical implementation — the VS Code packet-viewer webview
/// renders the layers this returns instead of re-implementing the protocol
/// in TypeScript. The MCP <c>net_disassemble</c> tool surfaces the same
/// output so AI agents can reason about captured packets.
///
/// Use <see cref="Dissect(byte[], int, MediusPortMap?)"/> as the entry point.
/// Pass a <see cref="MediusPortMap"/> built from the live Multiplayer config
/// so user-overridden ports are recognised; otherwise stock defaults apply.
/// </summary>
public static class PacketDissector
{
    // RT_MSG_TYPE values that carry a Medius APP payload (class + type bytes) on lobby connections.
    private static readonly HashSet<byte> s_appMsgTypes =
    [
        (byte)RT_MSG_TYPE.RT_MSG_SERVER_APP,
        (byte)RT_MSG_TYPE.RT_MSG_CLIENT_APP_TOSERVER,
        (byte)RT_MSG_TYPE.RT_MSG_CLIENT_MULTI_APP_TOSERVER,
        (byte)RT_MSG_TYPE.RT_MSG_SERVER_MULTI_APP_TOCLIENT,
    ];

    // RT_MSG_TYPE values that carry a DME app payload on a game (DME) connection: the above plus the
    // peer relay records (the server forwards relayed payloads to clients as CLIENT_APP_SINGLE).
    private static readonly HashSet<byte> s_dmeAppMsgTypes =
    [
        .. s_appMsgTypes,
        (byte)RT_MSG_TYPE.RT_MSG_CLIENT_APP_BROADCAST,
        (byte)RT_MSG_TYPE.RT_MSG_CLIENT_APP_SINGLE,
        (byte)RT_MSG_TYPE.RT_MSG_CLIENT_APP_LIST,
        (byte)RT_MSG_TYPE.RT_MSG_CLIENT_APP_BROADCAST_QOS,
        (byte)RT_MSG_TYPE.RT_MSG_CLIENT_APP_SINGLE_QOS,
        (byte)RT_MSG_TYPE.RT_MSG_CLIENT_APP_LIST_QOS,
        (byte)RT_MSG_TYPE.RT_MSG_UDP_APP,
    ];

    /// <summary>
    /// SOCOM II game messages and DME object classes used to decode DME app payloads. The bridge
    /// sets this from the embedded <c>Mods/SOCOM2/packets</c> JSON at startup; empty by default, in
    /// which case game messages show as "class 0x02 id 0x..".
    /// </summary>
    public static GameMessageCatalog GameCatalog { get; set; } = GameMessageCatalog.Empty;

    /// <summary>True for RT types whose payload is an app message on the given connection kind.</summary>
    public static bool IsAppRecord(RT_MSG_TYPE type, bool dmeConnection)
        => (dmeConnection ? s_dmeAppMsgTypes : s_appMsgTypes).Contains((byte)type);

    /// <summary>
    /// Bytes before the app payload in an APP record: the u16 target/source of APP_SINGLE and the
    /// [count][target u16 × count] list of APP_LIST.
    /// </summary>
    public static int AppPrefixLength(RT_MSG_TYPE type, ReadOnlySpan<byte> payload) => type switch
    {
        RT_MSG_TYPE.RT_MSG_CLIENT_APP_SINGLE or RT_MSG_TYPE.RT_MSG_CLIENT_APP_SINGLE_QOS => 2,
        RT_MSG_TYPE.RT_MSG_CLIENT_APP_LIST or RT_MSG_TYPE.RT_MSG_CLIENT_APP_LIST_QOS     => payload.Length > 0 ? 1 + payload[0] * 2 : 1,
        _ => 0,
    };

    // ── Public API ──────────────────────────────────────────────────────────

    /// <summary>
    /// Dissect a raw Ethernet frame into protocol layers.
    /// </summary>
    /// <param name="frame">Raw Ethernet frame bytes (starting at the destination MAC).</param>
    /// <param name="direction">0 = TX (PS2→Host), 1 = RX (Host→PS2), -1 = unknown.</param>
    /// <param name="ports">Resolved port map. Defaults to <see cref="MediusPortMap.Defaults"/>.</param>
    /// <returns>Ordered list of layers from outermost (Ethernet) to innermost (Medius payload).</returns>
    public static IList<DissectedLayer> Dissect(byte[] frame, int direction = -1, MediusPortMap? ports = null)
        => Dissect(frame, direction, ports, out _);

    /// <summary>One-line summary of a frame (server, protocol, endpoints, message names) for a packet table.</summary>
    public static PacketSummary Summarize(byte[] frame, int direction = -1, MediusPortMap? ports = null)
    {
        Dissect(frame, direction, ports, out var summary);
        return summary;
    }

    /// <summary>Dissect a frame and return its <see cref="PacketSummary"/> alongside the layers.</summary>
    public static IList<DissectedLayer> Dissect(byte[] frame, int direction, MediusPortMap? ports, out PacketSummary summary)
    {
        var portMap = ports ?? MediusPortMap.Defaults;
        var layers  = new List<DissectedLayer>();
        summary = new PacketSummary();
        if (frame.Length < 14)
        {
            summary.Protocol = "???";
            summary.Info     = "Frame too short";
            return layers;
        }
        var s = summary;

        // -- Ethernet II --
        string dstMac    = FmtMac(frame, 0);
        string srcMac    = FmtMac(frame, 6);
        ushort etherType = ReadU16BE(frame, 12);
        layers.Add(new DissectedLayer
        {
            Label  = "Ethernet II",
            Color  = "#5b9bd5",
            Offset = 0,
            Length = 14,
            Fields =
            [
                new("Destination", dstMac),
                new("Source",      srcMac),
                new("Type",        $"0x{etherType:X4} ({EtherTypeName(etherType)})"),
            ],
        });

        int off = 14;
        s.Source      = srcMac;
        s.Destination = dstMac;

        if (etherType == 0x0806)
        {
            DissectArp(frame, off, layers, s);
            return layers;
        }
        if (etherType != 0x0800) // IPv4 only beyond here
        {
            s.Protocol = $"ETH(0x{etherType:X4})";
            s.Info     = $"EtherType 0x{etherType:X4} ({EtherTypeName(etherType)})";
            return layers;
        }

        TryDissectIPv4(frame, off, direction, portMap, layers, s, out _, out _, out _, out _);
        return layers;
    }

    /// <summary>
    /// Parse SCERT messages from a TCP payload slice.
    /// Exposed separately so callers that have already decrypted a payload
    /// (or extracted it from a non-PCAP source) can run the SCERT parser
    /// directly without going through Ethernet/IP framing.
    /// </summary>
    /// <param name="tcpPayload">TCP payload bytes (already offset past the TCP header).</param>
    /// <param name="frameBase">Absolute offset of <paramref name="tcpPayload"/>[0] within the original frame, for frame-relative <see cref="ParsedScertMessage.FrameOffset"/> reporting.</param>
    /// <param name="dmeConnection">
    /// True on a game (DME) connection: app records then carry DME app messages (class 0 =
    /// <see cref="DmeAppMessageId"/>, class 2 = SOCOM II game messages) instead of Medius lobby messages.
    /// </param>
    public static IList<ParsedScertMessage> ParseScert(byte[] tcpPayload, int frameBase = 0, bool dmeConnection = false)
    {
        var msgs = new List<ParsedScertMessage>();
        int off  = 0;
        while (off < tcpPayload.Length)
        {
            // Need at least 3 bytes: type(1) + length(2)
            if (off + 3 > tcpPayload.Length) break;

            byte rawTypeByte = tcpPayload[off];
            bool isEncrypted = (rawTypeByte & 0x80) != 0;
            byte msgType     = (byte)(rawTypeByte & 0x7F);

            // Sanity: type must be a known SCERT value; bail if it looks like garbage.
            if (!Enum.IsDefined(typeof(RT_MSG_TYPE), msgType)) break;

            ushort payloadLen = ReadU16LE(tcpPayload, off + 1);
            int    hdrSize   = isEncrypted ? 7 : 3;
            int    totalSize = hdrSize + payloadLen;

            // Don't over-read beyond the buffer (fragmented segment — stop here).
            if (off + totalSize > tcpPayload.Length) break;

            uint? hash = isEncrypted ? ReadU32BE(tcpPayload, off + 3) : null;

            ParsedMediusMessage? medius          = null;
            IList<DissectedField>? scertFields   = null;
            IList<ParsedDmeMessage>? dme         = null;
            bool isAppMsg = IsAppRecord((RT_MSG_TYPE)msgType, dmeConnection);

            if (isAppMsg && dmeConnection)
            {
                // Encrypted records only decode after DecryptScertInPlace; ParseDmeApp rejects
                // anything that doesn't parse cleanly end to end, so ciphertext stays unlabelled.
                int appOff = off + hdrSize;
                int prefix = AppPrefixLength((RT_MSG_TYPE)msgType, tcpPayload.AsSpan(appOff, payloadLen));
                if (prefix < payloadLen)
                    dme = ParseDmeApp(tcpPayload.AsSpan(appOff + prefix, payloadLen - prefix), frameBase + appOff + prefix);
            }
            else if (isAppMsg && payloadLen >= 2)
            {
                int  appOff   = off + hdrSize;
                byte msgClass = tcpPayload[appOff];
                byte mType    = tcpPayload[appOff + 1];

                // Plausibility filter: when the record is still encrypted on
                // the wire, the bytes at appOff/appOff+1 are RC4 ciphertext —
                // reading them as (class, type) used to produce spectacularly
                // misleading labels (e.g. GetUniverse_ExtraInfo showing as
                // "AddToBuddyListFwdConfirmationRequest0" because cipher byte
                // 0x45 happens to match that enum value).
                //
                // Ciphertext bytes are uniformly random, so the chance of a
                // false positive (class ∈ {0..5} AND type defined in the
                // matching enum) is ≲ 1%. Records that this dissector callee
                // has explicitly decrypted via DecryptScertInPlace still pass
                // — that helper leaves the encrypted flag set so the +7 byte
                // header offset stays valid, but the now-plaintext class+type
                // ARE valid, so this check accepts them.
                bool plausible = !isEncrypted || LooksLikePlausibleMediusHeader(msgClass, mType);
                if (plausible)
                {
                    int  structKey = (mType << 8) | msgClass;
                    var  mediusPayload = tcpPayload.AsSpan(appOff + 2, payloadLen - 2).ToArray();
                    var  payloadFields = MediusStructSchemas.Medius.TryGetValue(structKey, out var def)
                        ? ParseMediusFields(def, mediusPayload)
                        : new List<DissectedField>();
                    medius = new ParsedMediusMessage
                    {
                        MsgClass      = msgClass,
                        MsgClassName  = MsgClassName(msgClass),
                        MsgType       = mType,
                        MsgTypeName   = MediusTypeName(msgClass, mType),
                        FrameOffset   = frameBase + appOff,
                        PayloadFields = payloadFields,
                    };
                }
            }
            else if (!isAppMsg && payloadLen > 0 && !isEncrypted)
            {
                if (MediusStructSchemas.ScertPayloads.TryGetValue(msgType, out var scertStruct))
                {
                    var scertPayload = tcpPayload.AsSpan(off + hdrSize, payloadLen).ToArray();
                    scertFields = ParseMediusFields(scertStruct, scertPayload);
                }
            }

            msgs.Add(new ParsedScertMessage
            {
                RawTypeByte        = rawTypeByte,
                MsgType            = (RT_MSG_TYPE)msgType,
                MsgTypeName        = ((RT_MSG_TYPE)msgType).ToString(),
                IsEncrypted        = isEncrypted,
                PayloadLen         = payloadLen,
                Hash               = hash,
                Medius             = medius,
                ScertPayloadFields = scertFields,
                Dme                = dme,
                FrameOffset        = frameBase + off,
                FrameLength        = totalSize,
            });

            off += totalSize;
        }
        return msgs;
    }

    /// <summary>
    /// Walk SCERT records inside <paramref name="frame"/>'s TCP payload and
    /// decrypt every record whose encrypted flag (0x80) is set, using
    /// <see cref="PS2_RC4"/> with the supplied 64-byte working key. Decryption
    /// is in-place — the buffer holds plaintext payloads after this returns.
    /// </summary>
    /// <param name="frame">Mutable raw Ethernet frame. TCP payload is rewritten in place.</param>
    /// <param name="workingKey">64-byte RC4 working key (the same one used to encrypt).</param>
    /// <param name="ports">Port map for locating the SCERT-carrying TCP segment. Defaults if null.</param>
    /// <returns>Number of records decrypted (zero if the frame carries no encrypted SCERT records).</returns>
    /// <remarks>
    /// Use case: the AI captures a SCERT trace, extracts the per-session RC4
    /// key from an earlier handshake, then calls this to make every later
    /// packet readable. Pairs with <see cref="Dissect"/> for full structured
    /// readout from a single key + frame.
    /// </remarks>
    public static int DecryptScertInPlace(byte[] frame, byte[] workingKey, MediusPortMap? ports = null)
    {
        if (workingKey.Length != 64) throw new ArgumentException("RC4 working key must be 64 bytes.", nameof(workingKey));
        var portMap = ports ?? MediusPortMap.Defaults;

        if (frame.Length < 34) return 0;
        if (((frame[12] << 8) | frame[13]) != 0x0800) return 0;            // IPv4 only
        int ihl = (frame[14] & 0xF) * 4;
        if (frame[23] != 6) return 0;                                       // TCP only
        int ipTotalLen = (frame[16] << 8) | frame[17];
        int tcpHdrOff  = 14 + ihl;
        if (frame.Length < tcpHdrOff + 20) return 0;
        int srcPort  = (frame[tcpHdrOff]     << 8) | frame[tcpHdrOff + 1];
        int dstPort  = (frame[tcpHdrOff + 2] << 8) | frame[tcpHdrOff + 3];
        if (!portMap.ScertPorts.Contains(srcPort) && !portMap.ScertPorts.Contains(dstPort)) return 0;

        int tcpHdr   = ((frame[tcpHdrOff + 12] >> 4) & 0xF) * 4;
        int payOff   = tcpHdrOff + tcpHdr;
        int payLen   = ipTotalLen - ihl - tcpHdr;
        if (payLen <= 0 || payOff + payLen > frame.Length) return 0;

        int decrypted = 0;
        int off = payOff;
        int end = payOff + payLen;
        while (off < end)
        {
            if (off + 3 > end) break;
            byte rawType = frame[off];
            byte msgType = (byte)(rawType & 0x7F);
            if (!Enum.IsDefined(typeof(RT_MSG_TYPE), msgType)) break;
            ushort recPayloadLen = (ushort)(frame[off + 1] | (frame[off + 2] << 8));
            bool encrypted = (rawType & 0x80) != 0;
            int hdr  = encrypted ? 7 : 3;
            int rec  = hdr + recPayloadLen;
            if (off + rec > end) break;

            if (encrypted && recPayloadLen > 0)
            {
                // SCERT encrypted layout: [type|0x80][lenLE:2][hash:4][cipher payload]
                // PS2_RC4 takes the 4-byte hash verbatim as IV. Decrypt the
                // payload in place; leave the encrypted flag + hash bytes
                // unchanged so Dissect's hdrSize=7 calculation still locates
                // the (now-plaintext) payload correctly. The label "Encrypted:
                // Yes" stays in the dissection so callers can see this record
                // *was* encrypted on the wire.
                byte[] hash = new byte[4];
                Array.Copy(frame, off + 3, hash, 0, 4);
                PS2_RC4.Decrypt(workingKey, hash, frame.AsSpan(off + 7, recPayloadLen));
                decrypted++;
            }

            off += rec;
        }
        return decrypted;
    }

    /// <summary>
    /// Split one DME app payload into its messages, the way <c>dme_objects.split</c> does: object
    /// update / create / destroy / end-of-batch, ping, server version and SOCOM II game messages.
    /// </summary>
    /// <param name="app">App payload (after any APP_SINGLE / APP_LIST target prefix).</param>
    /// <param name="frameBase">Absolute offset of <paramref name="app"/>[0] in the frame.</param>
    /// <returns>The messages, or null when the payload doesn't parse cleanly to its end (ciphertext, unknown ids).</returns>
    public static IList<ParsedDmeMessage>? ParseDmeApp(ReadOnlySpan<byte> app, int frameBase = 0)
    {
        var catalog = GameCatalog;
        var msgs = new List<ParsedDmeMessage>();
        int p = 0;
        while (p < app.Length)
        {
            if (p + 2 > app.Length) return null;
            byte cls = app[p], id = app[p + 1];
            var msg = new ParsedDmeMessage { MsgClass = cls, MsgId = id, FrameOffset = frameBase + p };
            int len;

            if (cls == (byte)NetMessageClass.MessageClassDME)
            {
                switch ((DmeAppMessageId)id)
                {
                    case DmeAppMessageId.ServerVersion:
                    {
                        len = Math.Min(app.Length - p, 2 + MediusConstants.DME_VERSION_LENGTH);
                        var ver = app.Slice(p + 2, len - 2);
                        int nul = ver.IndexOf((byte)0);
                        string text = Encoding.ASCII.GetString(nul < 0 ? ver : ver[..nul]);
                        msg.Fields.Add(new("Version", text));
                        msg.Display = $"ServerVersion \"{text}\"";
                        break;
                    }
                    case DmeAppMessageId.Ping:
                    {
                        len = Math.Min(app.Length - p, 2 + 8);
                        var b = app.Slice(p + 2, len - 2);
                        if (b.Length >= 4) msg.Fields.Add(new("Time Of Send", ReadU32LE(b, 0).ToString()));
                        if (b.Length >= 5) msg.Fields.Add(new("Ping Instance", b[4].ToString()));
                        if (b.Length >= 6) msg.Fields.Add(new("Request Echo", b[5] != 0 ? "true" : "false"));
                        msg.Display = b.Length >= 6 && b[5] == 0 ? "Ping (echo)" : "Ping";
                        break;
                    }
                    case DmeAppMessageId.ObjectUpdate:
                    {
                        if (p + 6 > app.Length) return null;
                        byte type = app[p + 2], n = app[p + 3];
                        ushort objId = ReadU16LE(app, p + 4);
                        if (!catalog.Classes.TryGetValue(type, out var cls0)) return null;
                        msg.Fields.Add(new("Class", $"{type} ({cls0.Name})"));
                        msg.Fields.Add(new("Object Id", $"0x{objId:X2} ({objId})"));
                        int q = p + 6;
                        for (int i = 0; i < n; i++)
                        {
                            if (q >= app.Length || app[q] >= cls0.Fields.Count) return null;
                            var f = cls0.Fields[app[q]];
                            if (q + 1 + f.Size > app.Length) return null;
                            msg.Fields.Add(new(f.Name, GameMessageCatalog.DecodeValue(f.Type, app.Slice(q + 1, f.Size))));
                            q += 1 + f.Size;
                        }
                        len = q - p;
                        msg.Display = $"ObjectUpdate {cls0.Name} #{objId}";
                        break;
                    }
                    case DmeAppMessageId.ObjectCreate:
                    {
                        if (p + 38 > app.Length) return null;
                        byte owner = app[p + 2], type = app[p + 3];
                        uint objId = ReadU32LE(app, p + 10);
                        var nameBytes = app.Slice(p + 22, 16);
                        int nul = nameBytes.IndexOf((byte)0);
                        string className = Encoding.Latin1.GetString(nul < 0 ? nameBytes : nameBytes[..nul]);
                        if (!catalog.Classes.TryGetValue(type, out var cls0) || p + 38 + cls0.RecordSize > app.Length) return null;
                        msg.Fields.Add(new("Owner", owner.ToString()));
                        msg.Fields.Add(new("Class", $"{type} ({cls0.Name})"));
                        msg.Fields.Add(new("Object Id", $"0x{objId & 0xFFFF:X2} ({objId & 0xFFFF})"));
                        msg.Fields.Add(new("Stamp", $"0x{ReadU32LE(app, p + 14):X8}"));
                        msg.Fields.Add(new("Object Name", className));
                        int q = p + 38;
                        foreach (var f in cls0.Fields)
                        {
                            msg.Fields.Add(new(f.Name, GameMessageCatalog.DecodeValue(f.Type, app.Slice(q, f.Size))));
                            q += f.Size;
                        }
                        len = q - p;
                        msg.Display = $"ObjectCreate {className} #{objId & 0xFFFF}";
                        break;
                    }
                    case DmeAppMessageId.ObjectDestroy:
                    {
                        if (p + 4 > app.Length) return null;
                        ushort objId = ReadU16LE(app, p + 2);
                        msg.Fields.Add(new("Object Id", $"0x{objId:X2} ({objId})"));
                        len = 4;
                        msg.Display = $"ObjectDestroy #{objId}";
                        break;
                    }
                    case DmeAppMessageId.EndOfBatch:
                        len = 2;
                        break;
                    default:
                        return null;
                }
                msg.Name = ((DmeAppMessageId)id).ToString();
            }
            else if (cls == (byte)NetMessageClass.MessageClassApplication && catalog.Messages.TryGetValue(id, out var def))
            {
                int size = def.Size ?? (app.Length - p - 2);
                if (p + 2 + size > app.Length) return null;
                var data = app.Slice(p + 2, size);
                foreach (var f in def.Fields)
                {
                    int w = GameMessageCatalog.TypeWidth(f.Type);
                    if (f.Offset > data.Length || (w > 0 && f.Offset + w > data.Length)) continue;
                    var slice = w > 0 ? data.Slice(f.Offset, w) : data[f.Offset..];
                    msg.Fields.Add(new(f.Name, GameMessageCatalog.DecodeValue(f.Type, slice)));
                }
                len = 2 + size;
                msg.Name    = def.Name;
                msg.IsGame  = true;
            }
            else
            {
                return null;
            }

            if (msg.Display.Length == 0) msg.Display = msg.Name;
            msg.Length = len;
            msgs.Add(msg);
            p += len;
        }
        return msgs.Count > 0 ? msgs : null;
    }

    /// <summary>
    /// Parse a Medius payload against an explicit struct definition. Useful when
    /// a caller already knows the class+type (e.g. when assembling synthetic
    /// packets or testing a payload extracted from a save).
    /// </summary>
    public static IList<DissectedField> ParseMediusFields(MediusStructDef def, byte[] payload)
    {
        var fields = new List<DissectedField>();
        int off    = 0;
        foreach (var f in def.Fields)
        {
            if (off >= payload.Length)
            {
                if (!f.Optional) break;
                continue;
            }
            int avail = Math.Min(f.Length, payload.Length - off);

            switch (f.Type)
            {
                case MediusFieldType.UInt:
                {
                    uint val = 0;
                    for (int i = 0; i < avail; i++) val |= (uint)payload[off + i] << (i * 8);
                    string? enumName = ResolveEnumName(f, val);
                    string  valStr   = enumName != null
                        ? $"{val} ({enumName})"
                        : $"{val} (0x{val:X})";
                    fields.Add(new DissectedField(f.Name, valStr));
                    break;
                }
                case MediusFieldType.AsciiZ:
                {
                    int end = off;
                    while (end < off + avail && payload[end] != 0) end++;
                    string str = Encoding.ASCII.GetString(payload, off, end - off);
                    fields.Add(new DissectedField(f.Name, str.Length > 0 ? str : "(empty)"));
                    break;
                }
                case MediusFieldType.Bool:
                {
                    uint val = 0;
                    for (int i = 0; i < avail; i++) val |= (uint)payload[off + i] << (i * 8);
                    fields.Add(new DissectedField(f.Name, val != 0 ? "true" : "false"));
                    break;
                }
                case MediusFieldType.Bytes:
                default:
                {
                    var sb = new StringBuilder(avail * 3);
                    bool allPrintable = true;
                    for (int i = 0; i < avail; i++)
                    {
                        byte b = payload[off + i];
                        if (i > 0) sb.Append(' ');
                        sb.Append(b.ToString("X2"));
                        if (!(b == 0 || (b >= 0x20 && b < 0x7F))) allPrintable = false;
                    }
                    if (allPrintable && avail > 0)
                    {
                        sb.Append("  \"");
                        for (int i = 0; i < avail; i++)
                        {
                            byte b = payload[off + i];
                            if (b != 0) sb.Append((char)b);
                        }
                        sb.Append('"');
                    }
                    fields.Add(new DissectedField(f.Name, sb.ToString()));
                    break;
                }
            }
            off += f.Length;
        }
        return fields;
    }

    // ── ARP / IPv4 / TCP / UDP / ICMP ────────────────────────────────────────

    private static void DissectArp(byte[] raw, int off, List<DissectedLayer> layers, PacketSummary s)
    {
        s.Protocol = "ARP";
        if (raw.Length < off + 28) { s.Info = "Truncated ARP"; return; }
        int    op        = ReadU16BE(raw, off + 6);
        string senderMac = FmtMac(raw, off + 8);
        string senderIP  = FmtIP(raw, off + 14);
        string targetMac = FmtMac(raw, off + 18);
        string targetIP  = FmtIP(raw, off + 24);
        s.Info = op == 1 ? $"Who has {targetIP}? Tell {senderIP}"
               : op == 2 ? $"{senderIP} is at {senderMac}"
               : $"ARP opcode {op}";
        layers.Add(new DissectedLayer
        {
            Label  = "ARP",
            Color  = "#e6a23c",
            Offset = off,
            Length = 28,
            Fields =
            [
                new("Opcode",     op == 1 ? "1 (Request)" : op == 2 ? "2 (Reply)" : op.ToString()),
                new("Sender MAC", senderMac),
                new("Sender IP",  senderIP),
                new("Target MAC", targetMac),
                new("Target IP",  targetIP),
            ],
        });
    }

    private static bool TryDissectIPv4(
        byte[] raw, int off, int direction, MediusPortMap portMap, List<DissectedLayer> layers, PacketSummary s,
        out int proto, out int payOff, out int totalLen, out int ihl)
    {
        proto = 0; payOff = 0; totalLen = 0; ihl = 0;
        if (raw.Length < off + 20) { s.Protocol = "IPv4"; s.Info = "Truncated IPv4 header"; return false; }

        ihl       = (raw[off] & 0x0F) * 4;
        totalLen  = ReadU16BE(raw, off + 2);
        int  ttl  = raw[off + 8];
        proto     = raw[off + 9];
        string srcIP = FmtIP(raw, off + 12);
        string dstIP = FmtIP(raw, off + 16);
        int    ipId  = ReadU16BE(raw, off + 4);
        int    flagsFrag = ReadU16BE(raw, off + 6);
        int    flags     = (flagsFrag >> 13) & 0x7;
        int    fragOff   = flagsFrag & 0x1FFF;

        layers.Add(new DissectedLayer
        {
            Label  = "Internet Protocol Version 4",
            Color  = "#67c23a",
            Offset = off,
            Length = ihl,
            Fields =
            [
                new("Version",             ((raw[off] >> 4) & 0xF).ToString()),
                new("Header Length",       $"{ihl} bytes"),
                new("Total Length",        totalLen.ToString()),
                new("Identification",      $"0x{ipId:X4} ({ipId})"),
                new("Flags",               $"0x{flags:X}"),
                new("Fragment Offset",     fragOff.ToString()),
                new("TTL",                 ttl.ToString()),
                new("Protocol",            $"{proto} ({IpProtoName(proto)})"),
                new("Source Address",      srcIP),
                new("Destination Address", dstIP),
            ],
        });

        payOff = off + ihl;
        s.Source      = srcIP;
        s.Destination = dstIP;
        s.Protocol    = $"IP({proto})";
        s.Info        = $"{srcIP} → {dstIP}  {IpProtoName(proto)}";

        if (proto == 1) // ICMP
        {
            s.Protocol = "ICMP";
            if (raw.Length >= payOff + 8)
            {
                int icmpType = raw[payOff];
                s.Info = $"{IcmpTypeName(raw[payOff])} (type {raw[payOff]}, code {raw[payOff + 1]})";
                int icmpCode = raw[payOff + 1];
                int icmpId   = ReadU16BE(raw, payOff + 4);
                int icmpSeq  = ReadU16BE(raw, payOff + 6);
                layers.Add(new DissectedLayer
                {
                    Label  = "Internet Control Message Protocol",
                    Color  = "#909399",
                    Offset = payOff,
                    Length = Math.Min(8, raw.Length - payOff),
                    Fields =
                    [
                        new("Type",       $"{icmpType} ({IcmpTypeName(icmpType)})"),
                        new("Code",       icmpCode.ToString()),
                        new("Identifier", $"0x{icmpId:X4}"),
                        new("Sequence",   icmpSeq.ToString()),
                    ],
                });
            }
            return true;
        }

        if (proto == 6) // TCP
        {
            DissectTcp(raw, payOff, totalLen, ihl, srcIP, dstIP, direction, portMap, layers, s);
            return true;
        }

        if (proto == 17) // UDP
        {
            DissectUdp(raw, payOff, totalLen, ihl, srcIP, dstIP, portMap, layers, s);
            return true;
        }

        return true;
    }

    private static void DissectTcp(
        byte[] raw, int payOff, int totalLen, int ihl,
        string srcIP, string dstIP, int direction, MediusPortMap portMap,
        List<DissectedLayer> layers, PacketSummary s)
    {
        s.Protocol = "TCP";
        if (raw.Length < payOff + 20) { s.Info = "Truncated TCP header"; return; }

        int srcPort = ReadU16BE(raw, payOff);
        int dstPort = ReadU16BE(raw, payOff + 2);
        uint seqNum = ReadU32BE(raw, payOff + 4);
        uint ackNum = ReadU32BE(raw, payOff + 8);
        int dataOff = ((raw[payOff + 12] >> 4) & 0xF) * 4;
        int tcpFlags = raw[payOff + 13];
        int win      = ReadU16BE(raw, payOff + 14);

        var flagNames = new List<string>(6);
        if ((tcpFlags & 0x01) != 0) flagNames.Add("FIN");
        if ((tcpFlags & 0x02) != 0) flagNames.Add("SYN");
        if ((tcpFlags & 0x04) != 0) flagNames.Add("RST");
        if ((tcpFlags & 0x08) != 0) flagNames.Add("PSH");
        if ((tcpFlags & 0x10) != 0) flagNames.Add("ACK");
        if ((tcpFlags & 0x20) != 0) flagNames.Add("URG");

        string server = portMap.ServerFromPorts(srcPort, dstPort);
        string tcpLabel = server.Length > 0
            ? $"Transmission Control Protocol  [{server} :{(dstPort > srcPort ? dstPort : srcPort)}]"
            : "Transmission Control Protocol";

        layers.Add(new DissectedLayer
        {
            Label  = tcpLabel,
            Color  = "#e6a23c",
            Offset = payOff,
            Length = dataOff,
            Fields =
            [
                new("Source Port",      srcPort.ToString()),
                new("Destination Port", dstPort.ToString()),
                new("Sequence Number",  seqNum.ToString()),
                new("Acknowledgment",   ackNum.ToString()),
                new("Header Length",    $"{dataOff} bytes"),
                new("Flags",            $"0x{tcpFlags:X2} ({(flagNames.Count > 0 ? string.Join(", ", flagNames) : "none")})"),
                new("Window",           win.ToString()),
            ],
        });

        int tcpPayOff = payOff + dataOff;
        // Use IP total length to exclude Ethernet padding from TCP payload length.
        int tcpPayLen = Math.Min(totalLen - ihl - dataOff, raw.Length - tcpPayOff);

        s.Server      = server;
        s.Source      = $"{srcIP}:{srcPort}";
        s.Destination = $"{dstIP}:{dstPort}";
        s.Info        = $"{srcPort} → {dstPort} [{string.Join(", ", flagNames)}] Len={Math.Max(tcpPayLen, 0)}";
        if (server == "DNS") s.Protocol = "DNS";

        bool isScertPort = portMap.ScertPorts.Contains(srcPort) || portMap.ScertPorts.Contains(dstPort);
        if (tcpPayLen > 0 && server.Length > 0 && isScertPort)
        {
            var tcpPayload = raw.AsSpan(tcpPayOff, tcpPayLen).ToArray();
            var scertMsgs  = ParseScert(tcpPayload, tcpPayOff, dmeConnection: server == "DME");
            if (scertMsgs.Count > 0)
            {
                EmitScertLayers(scertMsgs, server, layers);
                SummarizeScert(scertMsgs, s);
                return;
            }
        }

        // Fallback: generic TCP data layer
        if (tcpPayLen > 0)
        {
            layers.Add(new DissectedLayer
            {
                Label  = $"Data ({tcpPayLen} bytes)",
                Color  = "#909399",
                Offset = tcpPayOff,
                Length = tcpPayLen,
                Fields = [new("Length", $"{tcpPayLen} bytes")],
            });
        }
    }

    private static void DissectUdp(
        byte[] raw, int payOff, int totalLen, int ihl, string srcIP, string dstIP,
        MediusPortMap portMap, List<DissectedLayer> layers, PacketSummary s)
    {
        s.Protocol = "UDP";
        if (raw.Length < payOff + 8) { s.Info = "Truncated UDP header"; return; }
        int srcPort = ReadU16BE(raw, payOff);
        int dstPort = ReadU16BE(raw, payOff + 2);
        int udpLen  = ReadU16BE(raw, payOff + 4);
        string server = portMap.ServerFromPorts(srcPort, dstPort);
        layers.Add(new DissectedLayer
        {
            Label  = server.Length > 0 ? $"User Datagram Protocol  [{server}]" : "User Datagram Protocol",
            Color  = "#409eff",
            Offset = payOff,
            Length = 8,
            Fields =
            [
                new("Source Port",      srcPort.ToString()),
                new("Destination Port", dstPort.ToString()),
                new("Length",           udpLen.ToString()),
            ],
        });

        // UDP length (not the frame length) bounds the payload so Ethernet padding is excluded.
        int udpPayLen = Math.Min(Math.Max(udpLen - 8, 0), raw.Length - payOff - 8);
        int udpPayOff = payOff + 8;
        s.Server      = server;
        s.Source      = $"{srcIP}:{srcPort}";
        s.Destination = $"{dstIP}:{dstPort}";
        s.Info        = $"{srcPort} → {dstPort} Len={udpPayLen}";
        if (udpPayLen <= 0) return;

        if (server == "DNS" && DissectDns(raw, udpPayOff, udpPayLen, layers, s)) return;

        // SCERT over UDP (NAT / aux-UDP): only accept a payload that parses into whole records.
        if (portMap.ScertPorts.Contains(srcPort) || portMap.ScertPorts.Contains(dstPort))
        {
            var payload = raw.AsSpan(udpPayOff, udpPayLen).ToArray();
            var scertMsgs = ParseScert(payload, udpPayOff, dmeConnection: server == "DME");
            if (scertMsgs.Count > 0 && scertMsgs.Sum(m => m.FrameLength) == udpPayLen)
            {
                EmitScertLayers(scertMsgs, server, layers);
                SummarizeScert(scertMsgs, s);
                return;
            }
        }

        layers.Add(new DissectedLayer
        {
            Label  = $"Data ({udpPayLen} bytes)",
            Color  = "#909399",
            Offset = udpPayOff,
            Length = udpPayLen,
            Fields = [new("Length", $"{udpPayLen} bytes")],
        });
    }

    /// <summary>Decode a DNS header + first question (DNAS host lookups). False if it isn't DNS.</summary>
    private static bool DissectDns(byte[] raw, int off, int len, List<DissectedLayer> layers, PacketSummary s)
    {
        if (len < 12) return false;
        int id      = ReadU16BE(raw, off);
        int flags   = ReadU16BE(raw, off + 2);
        int qdCount = ReadU16BE(raw, off + 4);
        int anCount = ReadU16BE(raw, off + 6);
        bool response = (flags & 0x8000) != 0;

        var name = new StringBuilder();
        int p = off + 12, end = off + len;
        while (qdCount > 0 && p < end && raw[p] != 0 && (raw[p] & 0xC0) == 0)
        {
            int n = raw[p];
            if (p + 1 + n > end) break;
            if (name.Length > 0) name.Append('.');
            name.Append(Encoding.ASCII.GetString(raw, p + 1, n));
            p += 1 + n;
        }
        int qType = p + 3 <= end ? ReadU16BE(raw, p + 1) : 0;

        var fields = new List<DissectedField>
        {
            new("Transaction Id", $"0x{id:X4}"),
            new("Flags",          $"0x{flags:X4} ({(response ? "response" : "query")}, rcode {flags & 0xF})"),
            new("Questions",      qdCount.ToString()),
            new("Answers",        anCount.ToString()),
        };
        if (name.Length > 0) fields.Add(new("Query", $"{name} (type {qType})"));
        layers.Add(new DissectedLayer
        {
            Label  = $"Domain Name System ({(response ? "response" : "query")})",
            Color  = "#b5c9e8",
            Offset = off,
            Length = len,
            Fields = fields,
        });
        s.Protocol = "DNS";
        s.Info     = $"{(response ? "Response" : "Query")} 0x{id:X4} {name}{(response ? $" ({anCount} answer{(anCount == 1 ? "" : "s")})" : "")}";
        if (name.Length > 0) s.Messages.Add(name.ToString());
        return true;
    }

    /// <summary>Fill the summary's protocol, message list and info from parsed SCERT records.</summary>
    private static void SummarizeScert(IList<ParsedScertMessage> msgs, PacketSummary s)
    {
        string proto = "SCERT";
        foreach (var m in msgs)
        {
            if (m.Dme is { } dme)
            {
                foreach (var d in dme) s.Messages.Add(d.Display);
                proto = dme.Any(d => d.IsGame) ? "Game" : proto == "Game" ? proto : "DME";
            }
            else if (m.Medius is { } med)
            {
                s.Messages.Add(med.MsgTypeName);
                if (proto == "SCERT") proto = "Medius";
            }
            else
            {
                bool app = IsAppRecord(m.MsgType, dmeConnection: true);
                s.Messages.Add(m.IsEncrypted && app ? $"{m.MsgTypeName} (encrypted)" : m.MsgTypeName);
            }
        }
        s.Protocol = proto;
        const int shown = 4;
        s.Info = string.Join(", ", s.Messages.Take(shown)) + (s.Messages.Count > shown ? $" (+{s.Messages.Count - shown} more)" : "");
    }

    private static void EmitScertLayers(IList<ParsedScertMessage> scertMsgs, string server, List<DissectedLayer> layers)
    {
        foreach (var msg in scertMsgs)
        {
            int    hdrLen          = msg.IsEncrypted ? 7 : 3;
            // For encrypted records the inner Medius bytes are still ciphertext,
            // so suffix "(encrypted)" rather than the bare RT_MSG name — this
            // makes capture tables read like "RT_MSG_CLIENT_APP_TOSERVER (encrypted)"
            // instead of just "RT_MSG_CLIENT_APP_TOSERVER" sitting next to plaintext
            // siblings that DO have a Medius name attached.
            string msgTypeDisplay =
                  msg.Medius != null   ? $"{msg.MsgTypeName}({msg.Medius.MsgTypeName})"
                : msg.Dme != null      ? $"{msg.MsgTypeName}({string.Join(", ", msg.Dme.Select(d => d.Name).Distinct())})"
                : msg.IsEncrypted      ? $"{msg.MsgTypeName} (encrypted)"
                :                        msg.MsgTypeName;

            layers.Add(new DissectedLayer
            {
                Label  = $"SCERT [{server}]  {msgTypeDisplay}",
                Color  = "#c792ea",
                Offset = msg.FrameOffset,
                Length = hdrLen,
                Fields =
                [
                    new("Server",         server),
                    new("Message Type",   $"0x{(byte)msg.MsgType:X2} — {msgTypeDisplay}"),
                    new("Encrypted",      msg.IsEncrypted ? $"Yes (hash: 0x{msg.Hash!.Value:X8})" : "No"),
                    new("Payload Length", $"{msg.PayloadLen} bytes"),
                ],
            });

            if (msg.Dme is { } dme)
            {
                foreach (var d in dme)
                {
                    var fields = new List<DissectedField>
                    {
                        new("Message Class", $"0x{d.MsgClass:X2} — {MsgClassName(d.MsgClass)}"),
                        new("Message Id",    $"0x{d.MsgId:X2} — {d.Name}"),
                        new("Length",        $"{d.Length} bytes"),
                    };
                    fields.AddRange(d.Fields);
                    layers.Add(new DissectedLayer
                    {
                        Label  = d.IsGame ? $"Game [SOCOM II]  {d.Display}" : $"DME  {d.Display}",
                        Color  = d.IsGame ? "#f2c55c" : "#ff9580",
                        Offset = d.FrameOffset,
                        Length = d.Length,
                        Fields = fields,
                    });
                }
            }
            else if (msg.Medius is { } m)
            {
                int mediusPayLen = msg.PayloadLen - 2;
                var fields = new List<DissectedField>
                {
                    new("Message Class",  $"0x{m.MsgClass:X2} — {m.MsgClassName}"),
                    new("Message Type",   $"0x{m.MsgType:X2} — {m.MsgTypeName}"),
                    new("Payload Length", $"{mediusPayLen} bytes"),
                };
                fields.AddRange(m.PayloadFields);
                layers.Add(new DissectedLayer
                {
                    Label  = $"Medius [{m.MsgClassName}]  {m.MsgTypeName}",
                    Color  = "#ff9580",
                    Offset = m.FrameOffset,
                    Length = 2,
                    Fields = fields,
                });

                if (m.PayloadFields.Count == 0 && mediusPayLen > 0)
                {
                    layers.Add(new DissectedLayer
                    {
                        Label  = $"Medius Payload ({mediusPayLen} bytes)",
                        Color  = "#909399",
                        Offset = m.FrameOffset + 2,
                        Length = mediusPayLen,
                        Fields = [new("Length", $"{mediusPayLen} bytes")],
                    });
                }
            }
            else if (msg.ScertPayloadFields is { Count: > 0 } scertFields)
            {
                var fields = new List<DissectedField>
                {
                    new("Length", $"{msg.PayloadLen} bytes"),
                };
                fields.AddRange(scertFields);
                layers.Add(new DissectedLayer
                {
                    Label  = $"SCERT Payload — {msg.MsgTypeName}",
                    Color  = "#b5c9e8",
                    Offset = msg.FrameOffset + hdrLen,
                    Length = msg.PayloadLen,
                    Fields = fields,
                });
            }
            else if (msg.PayloadLen > 0)
            {
                layers.Add(new DissectedLayer
                {
                    Label  = $"SCERT Payload ({msg.PayloadLen} bytes)",
                    Color  = "#909399",
                    Offset = msg.FrameOffset + hdrLen,
                    Length = msg.PayloadLen,
                    Fields = [new("Length", $"{msg.PayloadLen} bytes")],
                });
            }
        }
    }

    // ── Enum / class name resolution ─────────────────────────────────────────

    /// <summary>
    /// Heuristic: do the supplied class+type bytes look like a legitimately
    /// decoded Medius header, or like random ciphertext? Used to suppress
    /// false labels when an encrypted record's payload is still scrambled.
    /// </summary>
    /// <remarks>
    /// Two-stage check:
    ///   1. class byte must be a known <see cref="NetMessageClass"/> value (0–5).
    ///   2. type byte must be defined in the message-id enum that the class
    ///      routes to (Lobby / LobbyExt / DME). Per-PS2-overrides (0x62–0x65)
    ///      are also accepted because <see cref="MediusTypeName"/> renders them.
    /// </remarks>
    private static bool LooksLikePlausibleMediusHeader(byte msgClass, byte msgType)
    {
        if (msgClass > 5) return false;

        Type? enumType = msgClass switch
        {
            0 or 3       => typeof(MediusDmeMessageIds),
            1 or 2 or 5  => typeof(MediusLobbyMessageId),
            4            => typeof(MediusLobbyExtMessageId),
            _            => null,
        };
        if (enumType == null) return false;

        // The PS2 override range is always legitimate for Lobby-family classes.
        if ((msgClass == 1 || msgClass == 2 || msgClass == 5)
            && s_ps2LobbyOverrides.ContainsKey(msgType))
            return true;

        return Enum.IsDefined(enumType, msgType);
    }

    /// <summary>
    /// PS2-era overrides for Lobby-class message type bytes that share their
    /// id with a newer Medius name. SOCOM II et al. use the older meaning,
    /// which is what we display since this codebase emulates PS2.
    /// </summary>
    /// <remarks>
    /// Without this, <see cref="Enum.GetName(Type, object)"/> picks one of the
    /// duplicate enum members alphabetically — and for these four values the
    /// alphabetic winner is the WRONG one for PS2 traffic
    /// (InvitePlayerToClan beats TicketLogin, etc.). The mislabel is severe:
    /// a TicketLogin sent during initial auth shows up as "InvitePlayerToClan"
    /// in dissection, which makes the trace look like the client is sending
    /// clan invites before it has even logged in.
    /// </remarks>
    private static readonly Dictionary<byte, string> s_ps2LobbyOverrides = new()
    {
        [0x62] = "TicketLogin",          // vs. InvitePlayerToClan
        [0x63] = "TicketLoginResponse",  // vs. InvitePlayerToClanResponse
        [0x64] = "GetUniverse",          // vs. CheckMyClanInvitations
        [0x65] = "GetUniverseResponse",  // vs. CheckMyClanInvitationsResponse
    };

    /// <summary>
    /// Resolve a Medius message type byte to a symbolic name, handling the
    /// historical class-byte ambiguity in PS2-era titles.
    /// </summary>
    /// <remarks>
    /// Classes 2/3/5 (Application/LobbyReport/LobbyAuth) shared id spaces with
    /// the Lobby/DME tables in older Medius — class=5 (auth) routes lobby ids,
    /// class=3 (lobby-report) routes DME server ids, class=2 (app) routes lobby
    /// ids. If the class-specific lookup misses (e.g. encrypted payloads where
    /// the class byte is gibberish), fall back through Lobby → LobbyExt → DME
    /// rather than surface a bare hex byte.
    /// </remarks>
    internal static string MediusTypeName(byte msgClass, byte msgType)
    {
        // PS2-era overrides only apply when the on-the-wire class byte says
        // we're in a class that routes lobby ids (1/2/5). For other classes
        // 0x62–0x65 mean something else and the normal lookup is correct.
        if ((msgClass == 1 || msgClass == 2 || msgClass == 5)
            && s_ps2LobbyOverrides.TryGetValue(msgType, out var ps2Name))
            return ps2Name;

        string? name = msgClass switch
        {
            0           => SafeEnumName(typeof(MediusDmeMessageIds),   msgType),
            1 or 2 or 5 => SafeEnumName(typeof(MediusLobbyMessageId),  msgType),
            3           => SafeEnumName(typeof(MediusDmeMessageIds),   msgType),
            4           => SafeEnumName(typeof(MediusLobbyExtMessageId), msgType),
            _ => null,
        };
        if (name != null) return name;

        // Last-resort fallback (used when the class byte is gibberish — e.g.
        // the record is actually still encrypted). Apply the same PS2 override
        // here so the trace doesn't read as clan traffic when it isn't.
        if (s_ps2LobbyOverrides.TryGetValue(msgType, out var fallback))
            return fallback;

        return SafeEnumName(typeof(MediusLobbyMessageId),    msgType)
            ?? SafeEnumName(typeof(MediusLobbyExtMessageId), msgType)
            ?? SafeEnumName(typeof(MediusDmeMessageIds),     msgType)
            ?? $"0x{msgType:X2}";
    }

    /// <summary>
    /// Display name for a <see cref="NetMessageClass"/> byte. CLR enum members
    /// are <c>MessageClassLobby</c>/etc.; strip that prefix so labels match the
    /// short forms (Lobby, DME, LobbyExt) the TS dissector emitted.
    /// </summary>
    internal static string MsgClassName(byte msgClass)
    {
        var name = SafeEnumName(typeof(NetMessageClass), msgClass);
        if (name == null) return $"0x{msgClass:X2}";
        const string prefix = "MessageClass";
        return name.StartsWith(prefix, StringComparison.Ordinal) ? name[prefix.Length..] : name;
    }

    /// <summary>
    /// Resolve an enum value to a symbolic name. Trims namespace prefixes that
    /// match the type name (e.g. <c>MediusLanguage_USEnglish</c> → <c>USEnglish</c>)
    /// for cleaner display, matching the TS dissector's output.
    /// </summary>
    private static string? ResolveEnumName(MediusFieldDef f, uint val)
    {
        if (f.EnumDict is { } dict && dict.TryGetValue(val, out var dictName))
            return dictName;

        if (f.EnumType is { } enumType)
        {
            string? name = SafeEnumName(enumType, val);
            if (name == null) return null;

            // Strip a leading "{TypeName}_" prefix for readability when present.
            string typePrefix = enumType.Name + "_";
            if (name.StartsWith(typePrefix, StringComparison.Ordinal))
                return name[typePrefix.Length..];
            return name;
        }
        return null;
    }

    /// <summary>
    /// Wrapper over <see cref="Enum.GetName(Type, object)"/> that handles
    /// signed-enum-stored-as-unsigned and skips throwing on unknown values.
    /// </summary>
    private static string? SafeEnumName(Type enumType, uint val)
    {
        // For int-backed enums (most of ScertTypes), negative wire values are
        // stored as their two's-complement uint (-1 → 0xFFFFFFFF). Convert to
        // the underlying type before lookup.
        var underlying = Enum.GetUnderlyingType(enumType);
        object key = underlying == typeof(byte)  ? (object)(byte)val
                   : underlying == typeof(sbyte) ? (object)(sbyte)val
                   : underlying == typeof(short) ? (object)(short)val
                   : underlying == typeof(ushort)? (object)(ushort)val
                   : underlying == typeof(int)   ? (object)(int)val
                   : underlying == typeof(uint)  ? (object)val
                   : underlying == typeof(long)  ? (object)(long)val
                   : underlying == typeof(ulong) ? (object)(ulong)val
                   : val;
        return Enum.GetName(enumType, key);
    }

    // ── Byte readers / formatters ────────────────────────────────────────────

    private static ushort ReadU16BE(byte[] b, int o)
        => o + 1 < b.Length ? (ushort)((b[o] << 8) | b[o + 1]) : (ushort)0;

    private static ushort ReadU16LE(byte[] b, int o)
        => o + 1 < b.Length ? (ushort)(b[o] | (b[o + 1] << 8)) : (ushort)0;

    private static ushort ReadU16LE(ReadOnlySpan<byte> b, int o)
        => o + 1 < b.Length ? (ushort)(b[o] | (b[o + 1] << 8)) : (ushort)0;

    private static uint ReadU32LE(ReadOnlySpan<byte> b, int o)
        => o + 3 < b.Length ? (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) : 0u;

    private static uint ReadU32BE(byte[] b, int o)
        => o + 3 < b.Length
            ? (uint)((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3])
            : 0u;

    private static string FmtMac(byte[] b, int o)
        => o + 6 <= b.Length
            ? $"{b[o]:X2}:{b[o+1]:X2}:{b[o+2]:X2}:{b[o+3]:X2}:{b[o+4]:X2}:{b[o+5]:X2}"
            : "00:00:00:00:00:00";

    private static string FmtIP(byte[] b, int o)
        => o + 4 <= b.Length ? $"{b[o]}.{b[o+1]}.{b[o+2]}.{b[o+3]}" : "0.0.0.0";

    private static string EtherTypeName(ushort t) => t switch
    {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86DD => "IPv6",
        _      => "Unknown",
    };

    private static string IpProtoName(int p) => p switch
    {
        1  => "ICMP",
        6  => "TCP",
        17 => "UDP",
        _  => "Unknown",
    };

    private static string IcmpTypeName(int t) => t switch
    {
        0  => "Echo Reply",
        3  => "Destination Unreachable",
        8  => "Echo Request",
        11 => "Time Exceeded",
        _  => "Other",
    };
}
