# Binary Injection

Push your own binaries (code or data) into a connected PS2 over the Medius
`RT_MSG_SERVER_MEMORY_POKE` channel — the same channel SOCOM II's online code
module uses, here carrying **your** payloads.

## How it works

A binary is written to EE memory in chunks. Each chunk is one `SERVER_MEMORY_POKE`
with the retail wire format:

```
[destAddr : 4 bytes, little-endian]
[size     : 4 bytes, little-endian]   // = data length of this chunk
[data     : size bytes]
```

Default chunk size is **512 bytes** (what retail SOCOM II uses). Pokes are sent
**plaintext** (no RC4), matching the captured working-server stream.

If you set a **hook address**, after the blob is loaded the server writes a single
MIPS jump there:

```
J <entryPoint>      // 0x08000000 | ((entryPoint >> 2) & 0x03FFFFFF)
```

so the injected code actually runs. The jump is a **raw overwrite** of whatever
was at the hook address — it does not preserve the original instruction, so if you
need the original behaviour, handle that inside your own blob. `entryPoint`
defaults to the load address.

Addresses are EE virtual addresses written as hex strings (`"0x000A0000"`) or
decimal. Injection happens on the **lobby (MLS)** connection.

## Trigger 1 — automatic, at lobby (config)

Add an `Injections` array to the `Online` section of `config.json`. Every enabled
entry is sent the moment a player reaches the lobby:

```json
"Online": {
  "...": "...",
  "Injections": [
    {
      "Enabled": true,
      "Name": "mymod",
      "File": "mymod.bin",
      "LoadAddress": "0x000A0000",
      "HookAddress": "0x00120000",
      "EntryPoint":  "0x000A0000",
      "ChunkSize":   512
    }
  ]
}
```

| Field         | Required | Meaning |
|---------------|----------|---------|
| `Enabled`     | no (default `true`) | Disable without deleting the entry. |
| `Name`        | no | Label for logs. |
| `File`        | **yes** | `.bin` path: absolute, or relative to the server exe dir, or relative to `Data/`. |
| `LoadAddress` | **yes** | EE address the blob is written to. |
| `HookAddress` | no | Where to write the `J entry` jump. Omit for a load-only injection. |
| `EntryPoint`  | no | Jump target (defaults to `LoadAddress`). |
| `ChunkSize`   | no (default `512`) | Bytes per poke (clamped to 1–1024). |

An empty/absent `Injections` list = stock behaviour, nothing is sent.

## Trigger 2 — on-demand (drop folder)

Set a watched folder in config:

```json
"Online": { "...": "...", "InjectDropFolder": "C:\\socom\\inject" }
```

Drop a `*.json` **manifest** into that folder (same fields as an `Injections`
entry). The server loads the `.bin` (resolved next to the manifest first, then the
usual locations), sends it to **every connected console** immediately, logs the
result, and deletes the manifest so it doesn't re-fire. Ideal for iterating while
the game is running:

```json
{ "Name": "hello", "File": "hello.bin", "LoadAddress": "0x000A0000", "HookAddress": "0x00120000" }
```

## What you'll see in the log

```
[MLS] Injecting 'mymod' (4096 bytes) -> 0x000A0000
[MLS] Injected hook J 0x000A0000 @ 0x00120000
[MLS] Injected 4096 bytes @ 0x000A0000 (8 pokes)
```

## Programmatic API

`BaseMediusTcpServer` exposes:

- `InjectBinaryAsync(tcp, loadAddr, blob, hookAddr?, entryAddr?, chunkSize, ct)`
- `InjectIntoClientAsync(connectionId, loadAddr, blob, hookAddr?, entryAddr?, chunkSize, ct)`
- `InjectIntoAllAsync(loadAddr, blob, hookAddr?, entryAddr?, chunkSize, ct)`

## Notes / caveats

- Hooks target fixed EE addresses, so a blob built for one game build can crash a
  different build. Keep blobs matched to your disc/version.
- This is a powerful primitive (arbitrary memory writes into the console). Only
  inject code you trust / authored.
