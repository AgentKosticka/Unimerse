# Unimerse

A minimal, encrypted WebSocket chat system written in C# (C# 13, .NET 9). It consists of a library with networking and cryptography primitives, a console server, and a console client with a live UI.

License: GNU General Public License v3.0 (GPL-3.0)

---

## Repository layout

- `UnimerseLib/`
  - `Logger.cs` — color-capable logger with optional channel-backed output
  - `Network/`
    - `Packets.cs` — strongly typed packets used by the protocol
    - `PacketResponses.cs` — response helpers used by the packet dispatch pipeline
    - `NetworkCommunicator.cs` — shared base for client/server communicators
    - `WebSocketConnection.cs` — thin wrapper over client/server WebSocket operations
    - `ClientCommunicator.cs` — client handshake, authentication, send/receive loop
    - `ServerCommunicator.cs` — Kestrel host, `/chat` WebSocket, health check, broadcast logic
  - `Cryptography/`
    - `Cipher.cs` — RSA + ECDH key exchange, AES-GCM session, key storage support
    - `WindowsKeyProtector.cs` — DPAPI-based key protector for Windows
    - `Pbkdf2AesKeyProtector.cs` — PBKDF2 + AES key protector for non-Windows
  - `Interfaces/IKeyProtector.cs` — abstraction for protecting private keys at rest
- `UnimerseServer/`
  - `Program.cs` — console server hosting WebSocket endpoint and logs
- `UnimerseClient/`
  - `Program.cs` — console client with Spectre.Console live UI

Target framework for all projects: `.NET 9`

---

## What it does

- Starts a WebSocket server at a configurable TCP port (default 5000) with:
  - WebSocket endpoint: `/chat`
  - Health check endpoint: `/isvalidunimerseserver` (returns `OK/UNIMERSESERVER`)
  - Optional static file root: `./staticwebroot` (serves `/` and `index.html` if present)
- Connects a console client to the server over WS or WSS and performs an authenticated, encrypted session.
- Broadcasts chat messages from a sender to all connected clients.
- Provides rich console logging via Spectre.Console with a non-blocking channel mode for UIs.

---

## Protocol and packets

All messages are strongly typed `Packet` subclasses (see `UnimerseLib/Network/Packets.cs`). They serialize to a binary envelope that begins with a 4-byte length prefix (of JSON + 1), followed by a 1-byte packet ID, followed by the JSON body.

Packet types and IDs:

- `StatusPacket` (`ID = 0x01`) — status code exchange.
  - Known codes (see remark in source): `10 = OK`, `11 = Executed`, `20 = Rejected by receiver`, `21 = Invalid token`, `22 = Invalid command`, `23 = Invalid data`, `30 = Error executing command`.
- `ChatPacket` (`ID = 0x02`) — client-to-server chat message.
- `ChatBrodcastPacket` (`ID = 0x03`) — server-to-clients broadcast message with `Sender` and `Message`.
- `UDPBrodcastPacket` (`ID = 0xf0`) — UDP discovery payload (not used by current programs).
- `PublicKeysExchangePacket` (`ID = 0xf1`) — RSA + ECDH public keys and ECDH signature.
- `AuthPacket` (`ID = 0xf2`) — `Token` and `Username` used to authenticate a client.
- `ClientJoinedPacket` (`ID = 0xe1`) — someone joined with `Username`.
- `ClientLeftPacket` (`ID = 0xe2`) — someone left with `Username`.
- `ServerStatusPacket` (`ID = 0xe3`) — `CurrentUsers` and `Description` snapshot.

---

## Cryptography

Implemented in `UnimerseLib/Cryptography/Cipher.cs`:

- RSA: 2048-bit (static process-wide key in `Cipher`).
- ECDH: `nistP256` for key agreement.
- Symmetric cipher: AES-GCM (16-byte authentication tag).
- Session key derivation: `ECDiffieHellman.DeriveKeyFromHash` using SHA-256.
- Envelope for encrypted payloads:
  - 4-byte total length (sanity check)
  - 4-byte `nonce` length + `nonce`
  - 4-byte `tag` length + `tag`
  - 4-byte `ciphertext` length + `ciphertext`

Key storage:

- The server constructs `Cipher` with `storeRSAKey: true` (see `ServerCommunicator`), enabling persistence of the RSA private key to `%LOCALAPPDATA%/Unimerse/rsa-key.dat`.
- Key protection is platform-specific via `IKeyProtector`:
  - Windows: `WindowsKeyProtector` (DPAPI)
  - Non-Windows: requires `UNIMERSE_MASTER_PASSWORD` environment variable for `Pbkdf2AesKeyProtector`

ECDH authenticity:

- The ECDH public key is signed with the RSA private key (`Cipher.SignData`) and verified with the peer RSA public key (`Cipher.VerifySignedData`).

---

## Handshake and session flow

Client (`UnimerseLib/Network/ClientCommunicator.cs`):

1. Connect WebSocket to `{ws|wss}://{host}:{port}{path}` via `WebSocketConnection.ConnectAsync`.
2. Send `PublicKeysExchangePacket` (unencrypted).
3. Receive server `PublicKeysExchangePacket` (unencrypted) and call `cipher.SetPeerPublicKeys` (verifies signature, derives session key).
4. Send `AuthPacket` (encrypted) with `Token` and `Username`.
5. Receive `StatusPacket`:
   - `10` ? authenticated; start encrypted receive loop.
   - `21` ? invalid token; error.
   - `23` ? username already in use; error.

Server (`UnimerseLib/Network/ServerCommunicator.cs`):

1. Accept WebSocket at `/chat` via `WebSocketConnection.AcceptAsync`.
2. Receive `PublicKeysExchangePacket` (unencrypted), set peer keys (`Cipher.SetPeerPublicKeys`).
3. Send server `PublicKeysExchangePacket` (unencrypted).
4. Receive `AuthPacket` (encrypted). Reject if:
   - `Token != sharedSecret`, or
   - `Username` contains `[` or `]`.
5. Check uniqueness of `Username`. On success:
   - Send `StatusPacket { Code = 10 }` to the new client.
   - Add client to `ConnectedClients` and raise `ClientConnected`.
   - Broadcast `ClientJoinedPacket` to all clients.
   - Send `ServerStatusPacket` with `CurrentUsers` and `Description` to the new client.
6. Enter encrypted receive loop.

---

## Server behavior (`UnimerseServer/Program.cs`)

- Configuration constants:
  - `TcpPort = 5000`
  - `SecretToken = "unimerse-rocks"`
  - `Style = "deepskyblue1"`
- Starts `ServerCommunicator`, sets `sharedSecret`, attaches logging and `Error` handlers, and calls `Initialize()`.
- Subscribes to `PacketReceived` and:
  - Ignores `StatusPacket` with `Code == 10 || Code == 11` and `AuthPacket` (auth is handled internally).
  - For `ChatPacket`, sets `ServerPacketResponse.isBrodcast = true` and populates `ChatBrodcastPacket { Sender, Message }`.
  - Logs `StatusPacket` and unknown packets; cancels response.
- Calls `await comm.StartServerAsync(TcpPort)`.
- Switches logger to channel mode and drains log messages to the console in a loop.

Server HTTP surface (`ServerCommunicator`):

- `GET /isvalidunimerseserver` ? `OK/UNIMERSESERVER`
- `GET /` ? serves `./staticwebroot/index.html` if present
- `GET /chat` ? WebSocket endpoint (expects an upgrade request)
- `GET /favicon.ico` ? 204 No Content
- All other paths ? simple HTML error page

---

## Client behavior (`UnimerseClient/Program.cs`)

- Configuration constants:
  - `ListenTimeoutMs = 5000`
  - `SharedSecret = "unimerse-rocks"`
  - `Style = "springgreen3"`
- Prompts for a `Username` and constructs an endpoint (examples below).
- Calls `VerifyEndpointAccessible(endpoint, ListenTimeoutMs)` which performs an HTTP GET to:
  - `http://{host}:{port}/isvalidunimerseserver` when `UseTls == false`
  - `https://{host}:{port}/isvalidunimerseserver` when `UseTls == true`
- Connects to the WebSocket and starts a live UI (`Spectre.Console`) that:
  - Renders a header and a message list
  - Shows a blinking caret for input
  - Sends a `ChatPacket` on Enter
- Handles server packets:
  - `StatusPacket Code == 10` ? ignored (success ack)
  - `ClientJoinedPacket` / `ClientLeftPacket` ? presence changes
  - `ServerStatusPacket` ? server description and current users
  - `ChatBrodcastPacket` ? message with `Sender`
  - Others ? logged as unknown; cancels response

Endpoint examples:

```csharp
// Hosted behind TLS-terminating proxy (e.g., Cloudflare)
var endpoint = new ClientCommunicator.ServerEndpoint("api.anthe.win", 443, "/chat", true);

// Local development (pure WS)
var endpoint = new ClientCommunicator.ServerEndpoint("localhost", 5000, "/chat", false);
```

Note: The server speaks WS (no TLS). For hosted scenarios, terminate TLS at the edge (e.g., Cloudflare) and forward to the server over WS.

---

## Logging (`UnimerseLib/Logger.cs`)

- `Logger` renders to Spectre.Console by default and supports a channel-backed mode:
  - `EnableChannelMode()` queues log entries into `logger.logChannel`
  - UI loops poll the channel and render messages
- Log levels: `Debug`, `Info`, `Warning`, `Error`, `Required`
- `Logger.Format(...)` returns a Spectre.Markup-formatted string without emitting it

---

## Extensibility

Add new features primarily by creating new packets and handling them in `PacketReceived`.

1) Define a packet in `UnimerseLib/Network/Packets.cs`:

```csharp
public class MyCustomPacket : Packet
{
    public override byte ID => 0x42; // unique ID
    public string Payload { get; set; } = string.Empty;
}
```

2) Handle it on the server (or client):

```csharp
comm.PacketReceived += (p, response, source) =>
{
    var spr = (ServerPacketResponse)response;
    switch (p)
    {
        case MyCustomPacket mcp:
            spr.isBrodcast = false; // reply only to sender
            spr.packet = new StatusPacket { Code = 11 }; // Executed
            break;
    }
};
```

3) Send packets using existing helpers:

- Server ? `SendPacketAsync(Packet, ClientInfo)` or `SendBrodcastPacketAsync(Packet)`
- Client ? `SendPacketAsync(Packet)`

Because packet type discovery is reflection-based, new packet types are automatically recognized if their `ID` is unique within the assembly.

---

## Local vs hosted (WS/WSS)

- Local development: `UseTls = false` and the server port (default 5000).
- Hosted with TLS (e.g., Cloudflare Tunnel):
  - Run the server as-is (WS on port 5000).
  - Terminate TLS at the edge and proxy to `ws://localhost:5000/chat`.
  - In the client, `UseTls = true` and the public port (commonly 443).

The client’s health check uses the same host and port to `GET /isvalidunimerseserver`.

---

## Build & run

Prerequisites:

- .NET 9 SDK
- UTF-8 capable terminal

Server:

```bash
cd UnimerseServer
 dotnet run
```

Client:

```bash
cd UnimerseClient
 dotnet run
```

Both apps log extensively (`acceptedLevel = LogLevel.Debug`). The server listens on `TcpPort` (default 5000). The client prompts for a username and connects to the configured endpoint.

---

## Events and hooks

- `NetworkCommunicator.PacketReceived` — raised for every decoded packet with a `PacketResponse` you can modify.
  - Server: set `ServerPacketResponse.isBrodcast` and `packet` to broadcast; otherwise the framework replies to the originating client when you set `packet`.
  - Client: set `ClientPacketResponse.packet` to reply to the server.
- `ServerCommunicator.ClientConnected` / `ClientDisconnected` — lifecycle notifications.
- `NetworkCommunicator.Error` — surfaced exceptions.

---

## License

GNU General Public License v3.0 (GPL-3.0).