using Spectre.Console;
using System.Threading.Tasks;
using UnimerseLib.Cryptography;

namespace UnimerseLib.Network
{
    /// <summary>
    /// Handles the client-side WebSocket lifecycle, including secure handshakes and packet dispatch.
    /// </summary>
    public class ClientCommunicator : NetworkCommunicator, IDisposable
    {
        private WebSocketConnection? connection;

        /// <summary>
        /// Cipher responsible for negotiating and encrypting the client session.
        /// </summary>
        public Cipher cipher = new();

        /// <inheritdoc/>
        public override bool IsServer => false;
        public Task ConnectAsync(string host, int port, string username = "Unset")
            => ConnectAsync(new ServerEndpoint(host, port, "/chat", true), username);

        public readonly record struct ServerEndpoint(string Host, int Port, string Path, bool UseTls);

        /// <summary>
        /// Establishes a WebSocket connection, performs the key exchange, and authenticates the client.
        /// </summary>
        public async Task ConnectAsync(ServerEndpoint endpoint, string username = "Unset")
        {
            connection = await WebSocketConnection.ConnectAsync(endpoint.Host, endpoint.Port, endpoint.Path, cts.Token, logger, endpoint.UseTls);
            LogMessage(new Log($"Connected to server at {(endpoint.UseTls ? "wss" : "ws")}://{endpoint.Host}:{endpoint.Port}{endpoint.Path} (remote {connection.RemoteEndPoint})", logLevel: LogLevel.Debug));

            // Exchange public keys.
            var keys = new PublicKeysExchangePacket
            {
                RSAPublicKey = Cipher.RSAPublicKey,
                ECDHPublicKey = cipher.ECDHPublicKey,
                ECDHSignature = cipher.ECDHSignature
            };
            await SendPacketAsync(keys, sendUnencryptedPacket: true);

            LogMessage(new Log($"Sent public keys", logLevel: LogLevel.Debug));

            // Wait for server keys.
            var serverKeys = await ReceivePacketAsync(connection, null, expectUnencryptedPacket: true) ?? throw new Exception("Disconnected before server provided public keys");

            if (serverKeys is not PublicKeysExchangePacket sk)
                throw new Exception("Invalid response from server");

            cipher.SetPeerPublicKeys(sk.RSAPublicKey, sk.ECDHPublicKey, sk.ECDHSignature);

            LogMessage(new Log($"Received public keys", logLevel: LogLevel.Debug));

            // Send auth packet.
            var auth = new AuthPacket { Token = sharedSecret, Username = username };
            await SendPacketAsync(auth);

            // Wait for response.
            var response = await ReceivePacketAsync(connection, cipher) ?? throw new Exception("Disconnected during authentication handshake");

            if (response is not StatusPacket sp)
                throw new Exception("Invalid response from server");

            if (sp.Code == 10) LogMessage("Authenticated successfully.");
            else if (sp.Code == 21) throw new Exception("Invalid token");
            else if (sp.Code == 23) throw new Exception("Username already in use");
            else throw new Exception($"Unknown status code {sp.Code}");

            LogMessage(new Log($"Handshake complete", logLevel: LogLevel.Debug));

            // Start async receive loop.
            _ = ReceiveLoopAsync(connection, cipher);
        }

        /// <summary>
        /// Serializes and sends a packet to the server, encrypting it unless explicitly disabled.
        /// </summary>
        public Task SendPacketAsync(Packet p, bool sendUnencryptedPacket = false)
        {
            if (connection == null) throw new InvalidOperationException("Not connected");

            byte[] buf = p.Serialize();

            if (!sendUnencryptedPacket)
            {
                buf = cipher.Encrypt(buf);
            }

            return connection.SendBinaryAsync(buf, cts.Token);
        }
        /// <inheritdoc/>
        public override Task HandlePacketResponseAsync(PacketResponse pr)
        {
            if (pr is not ClientPacketResponse spr) return Task.CompletedTask;
            if (spr.canceled || spr.packet == null) return Task.CompletedTask;
            return SendPacketAsync(spr.packet);
        }

        /// <summary>
        /// Disposes network resources and cryptographic material in use by the client.
        /// </summary>
        public override void Dispose()
        {
            connection?.Dispose();
            cipher.Dispose();
            base.Dispose();
            GC.SuppressFinalize(this);
        }

        public async Task<bool> VerifyEndpointAccessible(ServerEndpoint endpoint, int listenTimeoutMs)
        {
            using HttpClient httpClient = new();
            try
            {
                string scheme = endpoint.UseTls ? "https" : "http";
                string url = $"{scheme}://{endpoint.Host}:{endpoint.Port}/isvalidunimerseserver";

                using var ctsTimeout = new CancellationTokenSource(listenTimeoutMs);
                var response = await httpClient.GetAsync(url, ctsTimeout.Token);

                if (response == null || !response.IsSuccessStatusCode) return false;

                string content = await response.Content.ReadAsStringAsync(ctsTimeout.Token);

                return content == "OK/UNIMERSESERVER";
            }
            catch (Exception ex)
            {
                LogMessage(new Log($"Endpoint verification failed: {ex.Message}", logLevel: LogLevel.Warning));
                return false;
            }
        }
    }
}
