using Spectre.Console;
using System.Threading;
using System.Threading.Tasks;
using UnimerseLib.Cryptography;

namespace UnimerseLib.Network
{
    /// <summary>
    /// Provides shared networking infrastructure for client and server communicators, including logging and packet dispatch.
    /// </summary>
    public abstract class NetworkCommunicator : IDisposable
    {
        public CancellationTokenSource cts { get; private set; } = new();

        public virtual bool IsServer { get; }

        /// <summary>
        /// Raised whenever a packet is fully deserialized and ready for processing.
        /// </summary>
        public event Action<Packet, PacketResponse, WebSocketConnection?>? PacketReceived;
        /// <summary>
        /// Raised when an exception occurs within the communicator.
        /// </summary>
        public event Action<Exception>? Error;

        public Logger? logger;

        /// <summary>
        /// Shared secret used during the authentication handshake.
        /// </summary>
        public string sharedSecret = "unimerse-rocks";

        /// <summary>
        /// Invoked when child implementations request that a packet be sent in response to a received payload.
        /// </summary>
        public abstract Task HandlePacketResponseAsync(PacketResponse pr);

        /// <summary>
        /// Bubbles an exception through the <see cref="Error"/> event.
        /// </summary>
        private protected virtual void OnError(Exception ex) => Error?.Invoke(ex);
        /// <summary>
        /// Routes packets to subscribers and evaluates response directives.
        /// </summary>
        private protected virtual void OnPacketReceived(Packet p, WebSocketConnection? source = null)
        {
            PacketResponse response = IsServer
                ? new ServerPacketResponse(respondTo: source)
                : new ClientPacketResponse();

            PacketReceived?.Invoke(p, response, source);

            if (response.canceled || response.packet == null)
            {
                return;
            }

            HandlePacketResponseAsync(response);
        }

        /// <summary>
        /// Continuously reads packets from the provided connection until cancellation or disconnect.
        /// </summary>
        private protected async Task ReceiveLoopAsync(WebSocketConnection connection, Cipher cipher)
        {
            LogMessage(new Log("Starting receive loop", prefix: "Network", logLevel: LogLevel.Debug));
            try
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    var p = await ReceivePacketAsync(connection, cipher).ConfigureAwait(false);
                    if (p == null)
                    {
                        break;
                    }

                    OnPacketReceived(p, connection);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { OnError(ex); }
        }

        /// <summary>
        /// Reads a single packet from the wire and optionally decrypts it using the supplied cipher.
        /// </summary>
        private protected async Task<Packet?> ReceivePacketAsync(WebSocketConnection connection, Cipher? cipher, bool expectUnencryptedPacket = false)
        {
            byte[]? payload = await connection.ReceiveAsync(cts.Token).ConfigureAwait(false);
            if (payload == null)
            {
                return null;
            }

            if (!expectUnencryptedPacket)
            {
                if (cipher == null)
                {
                    throw new ArgumentNullException(nameof(cipher), "Cipher cannot be null when expecting encrypted packets.");
                }

                payload = cipher.Decrypt(payload);
            }

            return Packet.Deserialize(payload);
        }
        /// <summary>
        /// Performs common initialization and invokes the derived setup routine.
        /// </summary>
        public void Initialize()
        {
            InitializeChild();

            LogMessage("Initialized");
        }
        /// <summary>
        /// Allows derived communicators to run custom initialization logic.
        /// </summary>
        private protected virtual void InitializeChild() { }

        /// <summary>
        /// Logs a formatted message using either the configured logger or the console.
        /// </summary>
        public void LogMessage(string message, string? prefix = null, string? style = null, bool brackets = true, LogLevel logLevel = LogLevel.Info)
        {
            if (logger != null)
            {
                logger.LogMessage(new Log(message, prefix, style, brackets, logLevel));
            }
            else
            {
                Console.WriteLine($"[{prefix}] {message}");
            }
        }

        /// <summary>
        /// Writes a pre-constructed log entry using the available logging backend.
        /// </summary>
        public void LogMessage(Log log)
        {
            if (logger != null)
            {
                logger.LogMessage(log);
            }
            else
            {
                Console.WriteLine($"[{log.Prefix}] {log.Message}");
            }
        }

        /// <summary>
        /// Finalizer in case Dispose is not explicitly invoked.
        /// </summary>
        ~NetworkCommunicator()
        {
            Dispose();
        }

        /// <summary>
        /// Cancels outstanding operations and suppresses finalization.
        /// </summary>
        public virtual void Dispose()
        {
            cts.Cancel();
            GC.SuppressFinalize(this);
        }
    }
}
