# Unimerse ?

A simple, secure chat over WebSockets. Run the server, start the client, pick a username, and chat in your terminal. Works locally over WS and on the internet over WSS (e.g., via Cloudflare Tunnel).

License: GPL-3.0

---

## Quick start ??

1) Start the server:

```bash
cd UnimerseServer
 dotnet run
```

2) Start the client (in another terminal):

```bash
cd UnimerseClient
 dotnet run
```

3) Enter a username and start chatting. For now, messages are broadcast to all connected users.

---

## Features ??

- Terminal chat client with a live view (Spectre.Console)
- Real-time messaging over WebSockets (`/chat`)
- Simple health check endpoint (`/isvalidunimerseserver`)
- Secure session: authenticated and encrypted end-to-end
- Colorful logging with optional async mode

---

## Project layout ???

| Project | What it is |
|---|---|
| `UnimerseServer` | Console app that hosts the WebSocket server and logs activity |
| `UnimerseClient` | Console app with a live UI for chatting |
| `UnimerseLib` | Shared library: networking, packets, encryption, and logging |

Key files (accurate to the code):

- `UnimerseLib/Network/Packets.cs` — the message types used by the chat
- `UnimerseLib/Network/ServerCommunicator.cs` — HTTP + WebSocket server, broadcast logic
- `UnimerseLib/Network/ClientCommunicator.cs` — connects, authenticates, sends/receives
- `UnimerseLib/Network/WebSocketConnection.cs` — WebSocket wrapper
- `UnimerseLib/Network/PacketResponses.cs` — response helpers for handling packets
- `UnimerseLib/Cryptography/Cipher.cs` — session key setup + AES-GCM encryption
- `UnimerseLib/Logger.cs` — colorful logging with optional channel mode
- `UnimerseServer/Program.cs` — server setup and packet handling
- `UnimerseClient/Program.cs` — client UI and packet handling

---

## How to connect ??

Choose an endpoint:

```csharp
// Hosted (TLS terminated at a proxy, e.g., Cloudflare)
var endpoint = new ClientCommunicator.ServerEndpoint("api.anthe.win", 443, "/chat", true);

// Local development (no TLS)
var endpoint = new ClientCommunicator.ServerEndpoint("localhost", 5000, "/chat", false);
```

Before connecting, the client checks:

- `http(s)://{host}:{port}/isvalidunimerseserver` must respond with `OK/UNIMERSESERVER`

If OK, the client connects to `{ws|wss}://{host}:{port}/chat` and starts the chat.

---

## Chat flow ??

- Join with a unique username and a shared secret (must match server): `"unimerse-rocks"`
- Send a message ? server broadcasts to all users
- See join/leave notices and a server status snapshot (current users + description)

Packet types used by the app:

| Packet | Direction | Purpose |
|---|---|---|
| `AuthPacket` | Client ? Server | Username + shared secret |
| `StatusPacket` | Both | Status codes (e.g., `10` = OK) |
| `ChatPacket` | Client ? Server | Chat message |
| `ChatBrodcastPacket` | Server ? Clients | Chat message with sender |
| `ClientJoinedPacket` | Server ? Clients | Someone joined |
| `ClientLeftPacket` | Server ? Clients | Someone left |
| `ServerStatusPacket` | Server ? Client | Users list + description |

---

## Local vs hosted ??

- Local: server listens on `5000` over WS; client uses `UseTls = false`
- Hosted: keep the server on WS; terminate TLS at the edge (e.g., Cloudflare Tunnel) and connect with `UseTls = true` (commonly port `443`)

---

## Logging ??

- Colorful, formatted logs
- Optional channel mode so UIs can render smoothly
- Levels: Debug, Info, Warning, Error, Required

---

## Requirements ??

- .NET 9 SDK
- A UTF-8 capable terminal

---

## Troubleshooting ???

- "Cannot reach server" ? Is the server running? Does `/isvalidunimerseserver` return `OK/UNIMERSESERVER` on the host/port you chose?
- "Invalid token" ? Client and server must share the same secret: `"unimerse-rocks"`
- "Username already in use" ? Pick another username
- Local connect issues ? Make sure you’re using port `5000` and `UseTls = false`

---

## Technical deep-dive ??

This section summarizes exact specs implemented in the code.

### Transport & endpoints

- WebSocket endpoint: `/chat` (server validates upgrade requests)
- Health check: `GET /isvalidunimerseserver` ? `OK/UNIMERSESERVER`
- Optional static root: `./staticwebroot` for `GET /`

### Packet format (accurate to `Packets.cs`)

- Base `Packet` serialized as: `[int lengthOfJsonPlus1][byte id][json bytes]`
- Known packet IDs:
  - `StatusPacket` ? `0x01`
  - `ChatPacket` ? `0x02`
  - `ChatBrodcastPacket` ? `0x03`
  - `UDPBrodcastPacket` ? `0xf0`
  - `PublicKeysExchangePacket` ? `0xf1`
  - `AuthPacket` ? `0xf2`
  - `ClientJoinedPacket` ? `0xe1`
  - `ClientLeftPacket` ? `0xe2`
  - `ServerStatusPacket` ? `0xe3`

Status codes (as remarked in source): `10=OK`, `11=Executed`, `20=Rejected`, `21=Invalid token`, `22=Invalid command`, `23=Invalid data`, `30=Error`.

### Handshake & session

Accurate to `ClientCommunicator.cs` and `ServerCommunicator.cs`:

1. Client connects to `{ws|wss}://{host}:{port}{path}`.
2. Client sends `PublicKeysExchangePacket` (unencrypted).
3. Server replies with `PublicKeysExchangePacket` (unencrypted).
4. Both sides verify ECDH signature and derive a shared AES key.
5. Client sends `AuthPacket` (encrypted) with secret + username.
6. Server replies with `StatusPacket` (e.g., `10` for success) and enters the encrypted receive loop.

Username rules enforced on server: rejects if token mismatches or username contains `[` or `]`; also rejects duplicates.

### Cryptography (accurate to `Cipher.cs`)

- RSA: 2048-bit (process-static `rsaOwn`), used to sign ECDH public key
- ECDH: `nistP256` for key agreement
- Symmetric: AES-GCM with 16-byte authentication tag
- Key derivation: `ECDiffieHellman.DeriveKeyFromHash` (SHA-256)
- Encrypted envelope layout:
  - `[int totalLength]`
  - `[int nonceLen][nonce]`
  - `[int tagLen][tag]`
  - `[int ctLen][ciphertext]`
  - Validates total length = `nonceLen + tagLen + ctLen + 12` (3 ints * 4 bytes)

Key storage:

- Server `Cipher` can persist RSA private key at `%LOCALAPPDATA%/Unimerse/rsa-key.dat` (Windows uses `WindowsKeyProtector`; other OSes require `UNIMERSE_MASTER_PASSWORD` for `Pbkdf2AesKeyProtector`).

---

## License ??

GPL-3.0