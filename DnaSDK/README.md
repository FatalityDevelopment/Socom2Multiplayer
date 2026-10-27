[README(1).md](https://github.com/user-attachments/files/33941024/README.1.md)
# DnaSDK — PlayStation 2 DNAS Development Kit

A reconstructed development kit for the original PlayStation 2 Dynamic Network Authentication System (DNAS), providing protocol handling, cryptography, client/server authentication, and SSL/TLS communication for authentic, dynamically generated DNAS sessions.

This presents DnaSDK as an actual development kit, rather than simply a reverse-engineering research project.

DnaSDK is an effort to document and reconstruct what the original PlayStation 2 DNAS software actually does: the legacy SSL/TLS transport, HTTP message framing, packet formats, console/disc/title proofs, cryptographic transformations, stateful request/response exchange, and native client-side checks. Its purpose is **interoperability and preservation**, not simply returning a captured packet or patching a game to skip authentication.

DnaSDK implements a working, dynamically generated six-message DNAS authentication exchange. Unmodified retail clients have successfully authenticated in live testing, including **SOCOM II** (r0001 and r0004) and **Ratchet & Clank**. The server does not replay archived replies or modify the retail game to skip authentication. Instead, **original captured DNAS responses preserve the authentic 128-byte RSA-signed ticket**, and DnaSDK can use that preserved signed material to construct a **new, session-specific exchange** that the original client's own authentication code verifies. A captured ticket supplies the original signing authority; the surrounding protocol messages, challenges, session state and encryption are reconstructed and generated live.

Unlike projects that rely on replaying previously captured packet sessions, **DnaSDK reconstructs the DNAS authentication protocol and generates responses dynamically.** Packet replay-based implementations can encounter compatibility issues because recorded sessions reflect specific connection parameters, authentication states, and game revisions. Titles such as SOCOM II issue different requests depending on their patch or update revision, meaning a captured session from one revision may not satisfy the authentication requirements of another, as demonstrated with SOCOM II r0001.

DnaSDK addresses these limitations through its reconstruction of the live challenge-response and validation processes. By dynamically processing incoming requests and generating the appropriate cryptographic responses, while utilizing the preserved original RSA signature required by the unmodified retail client, **DnaSDK can successfully authenticate retail clients without relying on prerecorded packet sequences.** This allows it to accommodate differences between supported game revisions, complete the required authentication phases, and maintain compatibility with the original, unmodified PlayStation 2 software.

This project is independent research. It is not affiliated with or endorsed by Sony Interactive Entertainment or any game publisher. “DNAS” and “PlayStation” are trademarks of their respective owners.

## Contents

- [Why this project exists](#why-this-project-exists)
- [What makes it different](#what-makes-it-different)
- [Why preserved captures enable real authentication](#why-preserved-captures-enable-real-authentication)
- [How an authentication exchange works](#how-an-authentication-exchange-works)
- [Transport: the original PS2 SSL/TLS connection](#transport-the-original-ps2-ssltls-connection)
- [Binary packet header](#binary-packet-header)
- [Operation bytes and message families](#operation-bytes-and-message-families)
- [Six-message packet layouts](#six-message-packet-layouts)
- [Cryptography and why it works](#cryptography-and-why-it-works)
- [RSA tickets, moduli, and preservation archives](#rsa-tickets-moduli-and-preservation-archives)
- [Implementation scope](#implementation-scope)
- [Architecture](#architecture)
- [Setup and running](#setup-and-running)
- [Captures, diagnostics, and live packet experiments](#captures-diagnostics-and-live-packet-experiments)
- [Research method and evidence](#research-method-and-evidence)
- [Contributing and preservation](#contributing-and-preservation)
- [Acknowledgments and credits](#acknowledgments-and-credits)
- [References](#references)

## Why this project exists

DNAS (Dynamic Network Authentication System) was Sony's authentication system for PlayStation 2 online software. A game could ask the DNAS client to collect evidence associated with the console, disc and executable and exchange protected messages with Sony's service before allowing online functionality.

When official infrastructure disappeared, the authentication step became a barrier to preserving otherwise-functional online games. The community has spent years archiving original messages, keeping replacement servers running, documenting the protocols and preserving the knowledge needed to keep these titles usable.

A captured exchange is valuable evidence, but it does not by itself tell us **why** a packet is accepted. DnaSDK aims to recover the underlying protocol rather than build a collection of special-case replay scripts. Ideally, adding a supported title should mean supplying its original identity/authorization material, not writing a separate hard-coded implementation for that game.

## What makes it different

**DnaSDK is a live DNAS protocol implementation, not a packet-replay server and not a modified-client workaround.** Original, unmodified PlayStation 2 software makes the requests and performs its own checks. DnaSDK generates the responses those checks expect.

- Decodes the client's **C1 identity/proof structure** and derives session-dependent information from the request actually received.
- Creates new **S1 headers, eight-byte session identifiers, challenges and encrypted fields** for the active exchange.
- Maintains the same logical session across the multiple HTTP/TLS connections used by the retail client.
- Verifies the client's **C2 response** against the challenge actually issued in this session, rather than comparing it with a saved C2.
- Constructs new **S2 and S3** messages from the active exchange, rather than copying historical packets.
- Reuses the **original RSA-signed ticket preserved inside an authentic captured S1**. This ticket is preserved authorization material, not an old S1 response being replayed.
- Runs with the retail client's RSA public-key validation intact; no patched executable, modified DNAS module, or disabled verification step is required for a title with suitable preserved signed material.

### Archived signature versus replayed packet

An original S1 packet contains both **session-dependent fields** and a **128-byte RSA-signed ticket**. Those are not the same thing. The ticket is the portion that depends on the original signing authority. The other parts of the protocol can be reproduced for the current client request using the recovered native algorithms and demonstrated compatible field generation.

The distinction is important: **reusing a valid cryptographic signature is not replaying an entire authentication exchange**. A new session can contain newly generated challenges, encryption and continuation messages while carrying an already authentic signed record that the retail client validates normally.

## Why preserved captures enable real authentication

The preservation community recorded genuine DNAS traffic while the original authentication infrastructure was still available. In a preserved **authentic S1 response**, the server-issued RSA operand is present inside its encrypted payload. When that original packet is decoded correctly, the **signed operand survives as usable cryptographic material**.

```text
Preserved, original DNAS capture                   New live DnaSDK session
────────────────────────────────                   ───────────────────────
Captured C1 + encrypted S1                        Current retail C1
            │                                            │
            ▼                                            ▼
Decode S1's outer 3DES envelope                   Decode current C1 proofs
            │                                            │
            ▼                                            ▼
Recover the authentic 128-byte ticket             Generate new header, session ID,
            │                                    challenges and encrypted data
            │                                            │
            └───────────► Insert matching ticket ◄────────┘
                                   │
                                   ▼
                         Encrypt and transmit fresh S1
                                   │
                                   ▼
                  Original retail client verifies ticket
                  with its own built-in RSA public key
                                   │
                                   ▼
                       Generate and validate C2/S2/C3/S3
```

This explains **both why DnaSDK works and why the captures are so valuable**:

1. **The signature is genuine.** It was created by the historical signing authority and saved as part of the original server response; DnaSDK is not required to know the private RSA signing key.
2. **The signature can be retained while the session is renewed.** On tested retail paths, the original ticket is reusable with fresh, request-specific surrounding S1 fields. Its validity is checked by the unmodified client using the appropriate built-in public key.
3. **The protocol is regenerated.** The client supplies a new C1, DnaSDK calculates the corresponding encrypted fields and challenges, and the client answers the new challenge in C2. The old capture is **not** substituted for these live messages.
4. **The retail client performs the authentication checks.** Success does not depend on a patched game, a forced in-memory success result, or a server simply responding with a prerecorded completion packet.

**Crucial detail:** The 128-byte ticket is located at decrypted S1 absolute offset `0x48–0xC7` (body-relative `0x20–0x9F`). On the wire, S1's body is encrypted with the outer 3DES envelope. You must decode that envelope before treating this region as the RSA operand; slicing the same offsets directly out of encrypted wire bytes yields ciphertext, not the signature. The preserved capture must also match the appropriate title/key identity.

This is preservation through **authentic signed material plus reconstructed live protocol behavior**, not signature forgery or packet replay.

## How an authentication exchange works

For the common `0x08` family, the binary protocol consists of three request/response pairs. `C` means client-to-server and `S` means server-to-client.

```text
PS2 retail client                           DnaSDK server
      |                                           |
      |-- C1: identity + four wrapped proofs ---->|
      |                                           | validate C1; establish session
      |<-- S1: fresh challenge + RSA ticket ------| generate/encrypt S1
      |                                           |
      |-- C2: DES answer + RSA-decoded data ----->| validate challenge/continuation
      |<-- S2: marker + 128-byte data ------------| generate S2
      |                                           |
      |-- C3: final client parameter ------------>| validate session/phase
      |<-- S3: result flag + 32-byte data --------| generate completion reply
      |                                           |
```

**Each arrow is a complete DNAS message inside an HTTP body**, not a single TLS record. The retail client commonly establishes a new connection for subsequent exchanges; a TCP disconnect is **not** the end of the logical DNAS session. DnaSDK keys continuation exchanges to the eight-byte session ID and retains state until completion or expiration (currently 10 minutes idle).

For the canonical `0108` exchange the complete binary message sizes are:

| Step | Wire operation | Total bytes | Body bytes | Role |
|---|---|---:|---:|---|
| C1 | `01080000` | 308 | 268 | Initial identity/proof submission |
| S1 | `01080005` | 328 | 288 | Server challenge + signed RSA operand |
| C2 | `01080001` | 184 | 144 | Challenge response + decoded RSA data |
| S2 | `01080006` | 170 | 130 | Second server response |
| C3 | `01088008` | 44 | 4 | Final client request |
| S3 | `0108800D` | 77 | 37 | Final server result |

These opcodes are **four bytes**, written above in on-wire hexadecimal order.

## Transport: the original PS2 SSL/TLS connection

DNAS normally uses **TCP port 443** and an **HTTP/1.0-style request/response** within an encrypted connection. The PS2's old SSL implementation behaves differently from a modern TLS client:

1. Some retail clients transmit an **SSLv2-format ClientHello** as a compatibility wrapper, even though the resulting protected session is TLS-era.
2. DnaSDK's `Ssl2Adapter` converts the offered suites and client random into a form understood by the BouncyCastle TLS implementation. It does **not** invent cipher suites absent from the original ClientHello.
3. `LegacyTlsServer` preserves the correct handshake-transcript hashing for the **original SSLv2-format ClientHello bytes**. Simply translating the record without preserving those hash bytes can break the Finished verification.
4. The server negotiates legacy **TLS 1.0 / RSA / 3DES** where supported by the client and the installed crypto library, and avoids unsupported server extensions.
5. The client must accept the server's **X.509 certificate and issuer chain** before any DNAS message can be processed.
6. After successful negotiation, DnaSDK reads the HTTP headers, honors `Content-Length`, parses the binary DNAS body, and returns the reply with `HTTP/1.0 200 OK` and a body of the correct binary length.

The current HTTP response uses `Content-Type: image/gif` for compatibility with observed traffic; **the body is not a GIF**. It is a binary DNAS message.

**The transport TLS certificate and the DNAS RSA authentication ticket are completely different objects.** The certificate establishes the encrypted network connection. The 128-byte DNAS ticket is verified later by the game's native RSA logic. A working TLS certificate does **not** eliminate the need for a valid DNAS ticket.

> **Security:** TLS 1.0 and 3DES are obsolete. Run this service only in a controlled emulator environment or trusted retro-gaming LAN. Do not expose it as an Internet-facing general-purpose HTTPS server. Before publicly distributing certificate/private-key files, confirm that you have authorization to publish them; never accidentally commit credentials or private keys that should remain private.

## Binary packet header

Every common DNAS binary message starts with a **40-byte (`0x28`) header**. All multi-byte integer fields in the header are **big-endian**. Offsets below are relative to the **beginning of the DNAS binary message**, not the TCP, TLS or HTTP header.

| Offset | Length | Field | Confirmed meaning |
|---|---:|---|---|
| `0x00–0x03` | 4 | Operation | Version (1 byte), mode (1 byte), command (2 bytes) |
| `0x04–0x1A` | 23 | Header metadata | Preserved session/header material; subfields not fully identified |
| `0x1B–0x22` | 8 | Session ID | Connects C2/C3 to the server-generated S1 session |
| `0x23` | 1 | Header suffix | Observed header byte; full semantics unresolved |
| `0x24–0x27` | 4 | Body length | Big-endian 32-bit length of bytes following the 40-byte header |
| `0x28…` | Variable | Body | Structure depends on operation and mode |

For example, a 328-byte S1 has `0x00000120` (288 decimal) at offset `0x24`. The total length is **40 + 288 = 328**, not 288.

**Unknown does not mean unused.** DnaSDK labels unresolved metadata explicitly rather than assigning speculative identifiers to every byte. Mutation tests on standard S1 headers showed that several metadata bytes, the eight-byte session ID and suffix can vary while the retail client still accepts the exchange when the surrounding protocol is correct.

## Operation bytes and message families

The four-byte operation is decoded as:

```text
01 08 00 05
│  │  └────┴── command = 0x0005 (server's first reply)
│  └────────── mode    = 0x08
└───────────── version = 0x01
```

Some commands have bit `0x8000` set. The current parser exposes that bit separately from the lower 15-bit message value; its broader native semantics are still under investigation.

| Family | Example operations | What is known |
|---|---|---|
| `01 08` | `01080000`, `01080005`, `01080001`, `01080006`, `01088008`, `0108800D` | Canonical six-message exchange |
| `01 10` | Observed `0110`-family traffic | Shares major cryptographic structures; has family-specific command encoding |
| `01 18` | `01180000`, `01180005`, `01188001`, `01188006` | Alternate observed family; later commands use `0x8001` / `0x8006` |
| `01 22` | `01220000`, `01220005`, `01220001`, `01220006`, `01228003`, `01228007` | d-connect/variant family; terminal exchange differs |
| `01 90`, `01 98`, `01 A2` | Captured extended-family traffic | Additional packet formats observed; live producer coverage incomplete |

**Do not interchange modes by changing the second opcode byte.** These operation families have distinct validation and state expectations. The table documents observed wire values, not a guarantee that swapping a single byte yields another valid session.

The `0122` family has a distinct observed final exchange: client operation **`01228003`** and server result **`01228007`**, not an assumed `0108`-style `8008/800D` finish. One captured sequence used 48-byte C3 and 41-byte S3 packets; the client terminal body's full meaning is not yet mapped.

## Six-message packet layouts

**All offsets in the following tables include the 40-byte DNAS header.** An encrypted body's internal labels describe its layout **after the appropriate decryption**. The plaintext components are not necessarily visible in the raw on-wire ciphertext.

### C1 — initial client request (308 bytes)

| Absolute offset | Size | Contents |
|---|---:|---|
| `0x28` | 4 | Initial parameter `00 02 00 05` |
| `0x2C` | 8 | Lookup identifier (used with the request opcode to locate archival data) |
| `0x34` | 256 | Wrapped native C1 proof block |

After unwrapping the 256-byte proof block, its relative layout is:

| Unwrapped offset | Size | Contents |
|---|---:|---|
| `0x00` | 40 | Proof **A**, tied to console/CDVD-derived input |
| `0x28` | 56 | Proof **B**, initialized working input |
| `0x60` | 40 | Proof **D**, executable/game serial |
| `0x88` | 32 | Proof **C**, disc ReadKey identity |
| `0xA8` | 64 | Reserved zeros |
| `0xE8` | 16 | Session random material used in the wrapping process |
| `0xF8` | 8 | Fixed trailer `5A0698774DEAE638` |

**Important:** The original producer's conceptual order is A/B/C/D, but the **wire order is A/B/D/C**. These are encrypted native proof records, not merely four readable identity strings. Their internal verification combines recovered common tables, block-cipher transformations, source recovery, and consistency checks. The decoded title serial is a four-letter/five-digit identifier such as `SCUS97275`.

The preserved evidence also includes console i.Link identity, disc ReadKey identity, and CDVD-derived values. Some hardware-specific producer details and the full generalized client-side caller inputs remain research subjects; the server does not pretend a game serial alone determines the complete proof.

### S1 — first server response (328 bytes)

S1 has a **288-byte outer-3DES-encrypted body**:

| Decrypted absolute offset | Size | Meaning |
|---|---:|---|
| `0x28` | 8 | Challenge A; selects signed-image SHA-1 ranges for the retail client's DES-key calculation |
| `0x30` | 16 | DES-encrypted challenge data |
| `0x40` | 8 | Challenge B; randomized in supported experiments |
| `0x48` | 128 | **Original RSA-signed ticket** recovered from an authentic captured S1; validated by the retail client |
| `0xC8` | 32 | Inner 3DES-encrypted field, bound to this C1 |
| `0xE8` | 96 | Remaining S1 data; randomized successfully in supported experiments |

The 32-byte inner plaintext, after decrypting its own layer, was identical across **138 decoded standard S1 captures** covering modes `0x08`, `0x10` and `0x18`:

```text
E080764EF5C10C9736D6E3E94C23022F
4F09E0B7C614C2409A79A35CD7C4B7B7
```

This is a **shared protocol value**, not a title-specific RSA signature and not a captured response to replay. Its **wire ciphertext changes with C1** because its key and IV are derived from that request.

### C2 — client proof (184 bytes)

| Absolute offset | Size | Meaning |
|---|---:|---|
| `0x28` | 16 | Response to S1's DES challenge |
| `0x38` | 117 | RSA-decoded signed content returned by the retail client |
| `0xAD` | 11 | Reserved zero bytes |

The server validates the DES response against **the specific S1 it actually issued**. Where a verified title-specific public modulus is available, it can additionally check the returned 117-byte RSA data. The retail client performs its own RSA public-key verification regardless of whether DnaSDK has a local diagnostic modulus file.

### S2 — second server response (170 bytes)

| Absolute offset | Size | Meaning |
|---|---:|---|
| `0x28` | 2 | Marker `02 01` |
| `0x2A` | 128 | Second-response data |

Native-client studies and retail experiments showed that, on the studied common path, the client can accept freshly generated 128-byte data. DnaSDK generates those bytes, rather than replaying an archived S2. **The historical Sony backend's method of producing this data has not been fully recovered.**

### C3 — final client request (44 bytes; standard `0108`)

| Absolute offset | Size | Meaning |
|---|---:|---|
| `0x28` | 4 | Client-supplied final parameter |

The value is not constant across all captured clients. DnaSDK does not force it to match a recorded sample. `0122` uses a different terminal command/body family.

### S3 — final server reply (77 bytes; standard `0108`)

| Absolute offset | Size | Meaning |
|---|---:|---|
| `0x28` | 1 | Result flag (currently compatible completion value `00` for supported path) |
| `0x29` | 4 | Big-endian result length `00 00 00 20` (32) |
| `0x2D` | 32 | Result data |

The 32-byte result has been independently varied in successful retail experiments. This establishes client compatibility on those paths, **not** that the original service's account, region, entitlement, ban or other backend decision policy is fully known.

## Cryptography and why it works

### 1. Native C1 proof reconstruction

The C1 request contains four encrypted A/B/C/D proofs and a separately wrapped 256-byte structure. The project recovers the structure and native transformations, including cryptographic material shared by the SDK. It decodes the actual incoming proof records, verifies structural and native relationships, and obtains the title identity from them.

It **does not require guessing the client's pseudorandom generator seed** simply to invert the proof representation or establish the recovered fields' internal consistency. This matters because the original runtime draws random values and gathers clock/hardware evidence whose complete scheduling differs between callers. Derivation from what the client actually sent is preferable to guessing those unavailable runtime values.

A structurally valid C1 is **not** equivalent to an original Sony authorization decision. DnaSDK deliberately keeps cryptographic consistency and historical authorization policy separate.

### 2. S1's two encryption layers

The S1 body is encrypted with a protocol 3DES envelope. Inside the decrypted body, a **separate 32-byte region** is 3DES-encrypted using key material derived from that exact C1.

The code's request-bound derivation is:

```text
A = SHA1(C1[0x34 : 0x34 + 0x100])       // 256 bytes
B = SHA1(C1[0x48 : 0x48 + 0x0EC])       // 236 bytes
M = B[0:20] || A[0:12]                 // 32 bytes
3DES key = M[0:24]
3DES IV  = M[24:32]
```

This explains why the same shared 32-byte plaintext can produce **different encrypted bytes in every session**. A byte-for-byte copy of some other session's nested ciphertext is not generally equivalent to regenerating it from the current C1.

### 3. Challenge A and the image-independent DES calculation

The original client uses S1 Challenge A to choose three ranges of the DNAS image for SHA-1 calculations that contribute to an eight-byte DES key. The native code accepts ranges with **zero length**. If all three requested lengths are zero, each SHA-1 input is empty, independent of the image's contents.

Consequently, three identical empty-input digests XOR back to the same digest, making the challenge key derivable without guessing the specific signed image data. DnaSDK's current default Challenge A is eight zero bytes. This is based on an **actual retail acceptance experiment**, not a fake DES-success return.

This technique preserves the **real DES calculation and response check**; it does **not** establish that a particular image is genuine, replace C1 proof validation, or bypass RSA ticket verification.

### 4. RSA-1024 ticket verification

For a normal 128-byte signed operand `S`, the client performs an RSA public operation with its built-in key:

```text
M = S^65537 mod N
```

On the studied native path, the decoded 128-byte block has the type-1 structure:

```text
00 01 FF FF FF FF FF FF FF FF 00 [117 signed-content bytes]
```

The original unpadding routine checks the `00 01` marker, `FF` padding and separator; caller-side capacity checks additionally constrain the extracted output to **117 bytes**. A valid ticket preserved from an original capture already carries an authentic signature under the corresponding retail public key. DnaSDK does not need to create that signature again.

**A public modulus is not a signature.** Knowing `N` and `e` lets anyone verify or decode an existing operand; it does **not** provide the private signing exponent required to create a new one. **Preserved original S1 packets supply the already signed operand.** DnaSDK reuses that authentic material while generating the rest of the exchange anew, without claiming to forge Sony signatures or bypass the client's verification.

### 5. Later responses and state

S2 and S3 are built from the current session's phase and header. Randomized payloads are used **only where supported by actual retail experiments**. The server still checks operation ordering, session binding, DES challenge response and known frame structures. A correctly sized packet alone does not advance an invalid session.

## RSA tickets, moduli, and preservation archives

Original DNAS captures are more than protocol examples: **their genuine S1 replies preserve the signed RSA tickets required for normal retail verification**. This is why archival packet preservation is central to a *generative* DNAS implementation, even though the server does not replay archived packets.

DnaSDK distinguishes the two 128-byte RSA assets:

```text
RSA/
├── Signatures/
│   └── SCUS97275.BIN       # Authentic signed 128-byte ticket recovered from an original S1
├── Moduli/
│   └── SCUS97275.BIN       # Public RSA modulus (optional local diagnostic verification)
└── Decoded/
    └── SCUS97275.TXT       # Decoding / verification report where applicable
```

The **ticket** is supplied to the retail client inside a newly generated S1. The retail game already contains the corresponding public key and uses that key to verify the ticket. The **modulus** is a public verification value, useful for local analysis; it is not the signed ticket itself and cannot be substituted for it.

### How a capture becomes usable signed material

1. Identify a legitimate archived C1/S1 exchange for the relevant game identity and operation family.
2. Verify the captured S1 framing and decrypt its **outer 3DES body**.
3. Extract the **128-byte signed operand at decrypted absolute offset `0x48`** (S1 body offset `0x20`).
4. Associate it with the correct retail title/key identity. Where its public modulus is known, independently check the native RSA public operation and type-1 padding.
5. Supply those exact original signed bytes to the S1 producer. DnaSDK generates a **new** session header, challenge values, nested request-bound encryption and outer ciphertext for the current C1.
6. Let the **unmodified retail client** validate the ticket and respond to the *new* challenge; DnaSDK verifies that actual C2 and completes the remaining protocol stages.

An archived S1 is therefore an **input to the live response producer**, never the outgoing packet sent wholesale.

### DNASrep integration

DnaSDK's source contains an archive lookup for [DNASrep](https://github.com/FogNo23/DNASrep), using the incoming C1 lookup ID and operation to locate a matching preserved S1 in known regional layouts. Original packet preservation makes it possible to recover previously issued tickets for titles whose original signing service is unavailable.

The source snapshot reviewed for this documentation contains an important archive-import detail: `TicketStore.GetOrFetch` currently takes a raw S1 byte slice at `0x48`, while **the native signed operand is at that offset only after outer-body decryption**. An archive importer must decode the S1 body and validate the extracted ticket before caching it. This concerns **automatic archive extraction**, not the proven retail behavior of sessions supplied with authentic verified ticket material.

The original archive lookup root in the reviewed source is:

```text
https://raw.githubusercontent.com/FogNo23/DNASrep/master/www/dnas
```

A successful archive lookup alone does not prove a captured ticket matches every release, region or public-key identity. The surviving authentic signed record must correspond to the client actually being authenticated.

## Implementation scope

| Area | Implemented behavior / scope |
|---|---|
| Legacy PS2 TCP/TLS and HTTP transport | Working with tested retail clients using compatible certificates and handshakes |
| 40-byte header and common wire operations | Parsed and generated for the supported authentication families |
| Initial C1 proof processing | Native encrypted structure decoded and verified using recovered proof transformations |
| First S1 response | Newly generated metadata, session identifier, challenges and request-bound 3DES encryption |
| Original RSA authority | **Authentic signed ticket recovered from a suitable original capture**; no game modifications or forged signing key required |
| C2 verification | Validates the response to the **new challenge from the current session** |
| S2 and S3 responses | New compatible response content generated for successfully tested common exchanges |
| Session management | Tracks operation ordering and continuation across separate HTTP/TLS connections |
| Retail validation | Successfully completed full authentication on original clients, including SOCOM II r0001/r0004 and Ratchet & Clank |
| Extended operation families and historical backend policy | Additional research areas; not needed to describe the proven common authentication sequence |

The implementation reconstructs **client-visible authentication protocol behavior**. It does not claim to reproduce every historical internal Sony backend policy (such as account administration, entitlements, or enforcement decisions). That distinction does not diminish the successful end-to-end retail authentication demonstrated for the supported common path.

## Architecture

The code intentionally separates transport, protocol state, crypto and native-client research:

```text
Program.cs
TCP.TLS/                  Legacy PS2 SSL/TLS and certificate handling
TCP.Server/               TCP listener, HTTP framing and packet journals
DNAS.Server/              Packet layouts, session registry, response generation,
                          identity verification, ticket/archive handling
DNAS.Cryptography/        DES/3DES, RSA public verification, native proof routines,
                          request-bound hashes and protocol constants
DNAS.Client/              Standalone client simulation and native proof research
```

- **`TCP.TLS`** owns encryption *of the network connection*. It does not decide DNAS authorization.
- **`TCP.Server`** accepts one HTTP request per connection, logs it and passes the body to the DNAS processor.
- **`DNAS.Server`** validates the operation, recovers the C1 evidence, retains a session, selects a title-specific signed operand and produces the next packet.
- **`DNAS.Cryptography`** implements cryptographic operations and common recovered native functions without title-specific server shortcuts.
- **`DNAS.Client`** supplies test/simulation and native reconstruction utilities. It is not the retail game's client and its APIs explicitly reject calls that lack the original caller evidence.

A title serial determines lookup of suitable original signature assets; it is not a reason to insert `ReadSocomWhatever()`-style code into the shared cryptographic implementation. The protocol code is designed to stay game-independent.

## Setup and running

The current research distribution consists of C# source files. **Use the repository's own project/solution definition and dependencies** when building; source-only research archives may omit `.csproj` and `.sln` files. The live transport uses BouncyCastle TLS APIs.

1. Build the existing DnaSDK project in your configured .NET environment.
2. Provide PS2-compatible TLS certificate, RSA private key and CA certificate files. The current loader looks for the configured files or `TCP.TLS/Certificates/cert-us.pem`, `cert-us-key.pem`, and `ca-cert.pem`.
3. Supply authentic signed tickets extracted from matching original DNAS S1 captures in `RSA/Signatures/`. Archive retrieval is available in source; verify extraction from the encrypted archived body before relying on automatic imports.
4. Point an authorized test PS2/emulator client at the service's intended hostname and port. Name resolution and console network setup depend on your environment.
5. Start the server and inspect the packet captures and client outcome.

Example after building the executable:

```powershell
DnaSDK.exe --bind 0.0.0.0 --port 443 --capture-dir PacketLogs
```

Explicit certificate configuration:

```powershell
DnaSDK.exe --cert-pem cert.pem --key-pem key.pem --ca-cer ca.pem --capture-dir PacketLogs
```

Useful switches from the current CLI:

| Option | Purpose |
|---|---|
| `--bind IP` | Local address (default all interfaces) |
| `--port NUMBER` | TCP listen port (default 443) |
| `--capture-dir PATH` | Directory for binary incoming/outgoing captures and log files |
| `--cert-pem PATH`, `--key-pem PATH`, `--ca-cer PATH` | Explicit legacy TLS identity and issuer chain |
| `--pfx PATH`, `--pfx-password TEXT` | Alternative PFX certificate input |
| `--tls-hostname NAME` | Expected legacy gateway hostname configuration |
| `--rsa-dir PATH` | RSA signature/modulus asset root (default `RSA`) |
| `--dnasrep-url HTTPS_URL` | Override the archival repository root |
| `--console-id HEX8`, `--disc-id HEX5`, `--serial SERIAL` | Optional **joint** identity pinning for controlled tests |
| `--help` | Show current command-line help |

The three identity-pinning switches must be used together. `--s1-patch` is **experimental** and may deliberately cause retail authentication errors. It is not a bypass or a production requirement.

## Captures, diagnostics, and live packet experiments

The server records the **DNAS HTTP body bytes**, not encrypted TLS records. This matters because the binary offset descriptions in this README begin at the DNAS message's own byte zero.

Typical files include:

```text
PacketLogs/
├── Connections.log
├── Session1.log
├── Session1_Incoming_1.bin
├── Session1_Outgoing_1.bin
├── Session1_Incoming_2.bin
├── Session1_Outgoing_2.bin
└── ...
```

When an S1 mutation is requested, the current implementation additionally saves the **original unmodified S1** separately before sending the mutated packet. This makes a byte-for-byte comparison possible.

The server serializes a normal generated reply first, then modifies the outgoing byte array **immediately before the HTTP send**. This means the retail client—not a patched emulator instruction—is what decides whether the altered packet passes validation. The server's own session retains the canonical unmodified response.

For any claim about a native branch, report **both** the wire change and the executed native control flow. A reachable branch in a memory dump does **not** prove a legal packet can select it; the definitive test is whether an unmodified client validates the exchange and proceeds normally.

### Useful evidence to include in bug reports

- Game title and serial, region, SDK revision if known.
- Console/emulator environment and whether the game's executable was modified.
- Exact incoming/outgoing packet bytes, with sensitive identifiers redacted if necessary.
- Requested opcode, actual transmitted opcode, declared body length and actual body length.
- Native EE PC and registers **at the decision**, plus the caller and the selected branch.
- Whether the client sent C2/C3, the returned DNAS error, and whether it actually entered online mode.
- Whether the signed ticket was original, independently verified, absent or unknown.

## Research method and evidence

This reconstruction has been built through a combination of original archived packets, controlled mutation of genuinely generated replies, retail-client tests, EE memory dumps, and MIPS instruction tracing. Wherever possible, results are established at **both** the packet level and the native code level.

Examples of particularly useful confirmed observations:

- Reconstructed C1 can be **unwrapped into its actual A/B/D/C proof layout**, including expected reserved zeros and trailer.
- S1's nested 32-byte plaintext matched across 138 decoded archived responses in several standard modes.
- Standard S1 Challenge A can select zero-length image ranges, allowing a genuinely calculated image-independent DES reply on tested clients.
- Fresh challenges, metadata, session IDs and several later-response bytes were accepted by retail clients in controlled experiments.
- The common RSA decoded block carries **117 signed-content bytes** with type-1 padding. Its native caller enforces the decoded-content capacity.
- Authentic signed ticket material can be taken from a preserved original S1 and carried inside a **newly generated S1** for a fresh session, without replaying that historical response or altering the retail client's verification code.

Please keep **observed**, **reconstructed**, **inferred**, and **unknown** separate in new contributions. A packet capture proves what was sent; a disassembly provides candidate behavior; an executed native trace proves a particular branch was taken; a completed retail exchange proves compatibility in that tested configuration.

## Contributing and preservation

Useful contributions include original DNAS packet captures, confirmed title/serial mappings, regional differences, independently verified RSA public moduli, legitimately preserved original signed ticket material, native function traces, protocol documentation and reproducible tests. Please include the source and scope of evidence; don't silently replace an unknown field with a guessed meaning.

When sharing logs or captures, remove personal identifiers and private information where appropriate. Do not submit private keys or distribute copyrighted game/firmware material without permission. We are interested in recovering the protocol, **not** obtaining other users' credentials.

The long-term objective is a broadly usable **game-independent** DNAS implementation, with unsupported cases identified precisely enough for the community to investigate them instead of hiding failures behind per-title hacks.

## Acknowledgments and credits

**[FaTaLiTy] Antix — SSL/TLS system.** Special thanks and **full credit to [FaTaLiTy] Antix for the development, implementation, and successful operation of the SSL/TLS system** that enables communication with the original PlayStation 2 DNAS client. Antix developed the working SSL/TLS solution, including generating the compatible certificates, establishing the required secure handshake, and ensuring that retail PS2 clients could successfully establish encrypted connections with the server. This was a critical contribution to the project, providing the secure transport layer necessary for the reconstructed DNAS authentication protocol to operate with original, unmodified retail clients. **All credit for the SSL/TLS system and its functionality belongs to [FaTaLiTy] Antix.**

**DNASrep and the preservation community.** Our sincere thanks to everyone behind [DNASrep](https://github.com/FogNo23/DNASrep) and the broader preservation effort for **actively collecting, cataloguing and preserving as many authentic original DNAS packet exchanges as possible**. This work is fundamental to what DnaSDK can do: preserved responses contain the **original RSA-signed tickets** needed for real validation with unmodified retail clients, while the reconstructed protocol lets the server generate *new sessions* around those preserved signed artifacts. The archive is not merely a set of examples to compare against; it preserves cryptographic history that cannot simply be regenerated without the original signing authority.

## References
- **[[FaTaLiTy] Antix (TylerDev888)](https://github.com/TylerDev888)** — Developer of the SSL/TLS system used by DnaSDK, including the compatible certificates, secure handshake implementation, and encrypted communication support for original PlayStation 2 DNAS clients. Full credit for the SSL/TLS system belongs to **[FaTaLiTy] Antix**.
- [DNASrep — FogNo23](https://github.com/FogNo23/DNASrep): preservation archive

- Native code, source files and packet captures in this research project are the primary evidence for the detailed **offsets, operations and cryptographic calculations** in this document. Those specifics should not be inferred solely from community overview pages.

---

**Preserve the evidence. Reconstruct the behavior. Keep the original games working.**
