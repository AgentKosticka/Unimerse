using Spectre.Console;
using System.Text;
using UnimerseLib;
using UnimerseLib.Network;

namespace UnimerseServer
{
    public static class Program
    {
        // Configuration
        const int TcpPort = 5000;
        const string SecretToken = "unimerse-rocks";
        const string Style = "deepskyblue1";

        public readonly static Logger logger = new("Server", Style);

        static async Task Main()
        {
            // Ensure UTF-8 console
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.InputEncoding = System.Text.Encoding.UTF8;

            logger.acceptedLevel = LogLevel.Debug;

            // Initialize communicator
            using ServerCommunicator comm = new();

            comm.sharedSecret = SecretToken;
            comm.logger = logger;
            comm.Error += (ex) =>
            {
                logger.LogMessage(new Log($"Network error: {ex.Message}", logLevel: LogLevel.Error));
            };

            comm.Initialize();

            // Handle incoming packets
            comm.PacketReceived += (p, response, source) =>
            {
                ServerPacketResponse spr = (ServerPacketResponse)response;
                string senderName = comm.ConnectedClients
                    .Find(ci => ReferenceEquals(ci.Connection, source))?.Name ?? "Unknown";

                switch (p)
                {
                    // Ignored types:
                    case StatusPacket sp when sp.Code == 10 || sp.Code == 11: // Nothing is wrong
                    case AuthPacket ap: // Auth packets are handled internally
                        spr.Cancel();
                        break;


                    case StatusPacket sp:
                        logger.LogMessage(new Log($"Received status packet with code {sp.Code} from {source?.RemoteEndPoint}", logLevel: LogLevel.Warning));
                        spr.Cancel();
                        break;
                    case ChatPacket cp:
                        spr.isBrodcast = true;
                        spr.packet = new ChatBrodcastPacket { Sender = senderName, Message = cp.Message };
                        logger.LogMessage(new Log($"Received message [bold red]{cp.Message}[/] from [bold]{senderName}[/]", logLevel: LogLevel.Info));
                        break;
                    default:
                        logger.LogMessage(new Log($"Received unknown packet type {p.GetType().Name} from {source?.RemoteEndPoint}", logLevel: LogLevel.Warning));
                        spr.Cancel();
                        break;
                }
            };

            // Start server
            await comm.StartServerAsync(TcpPort);

            // Prepare UI thread elements
            // Switch logging to channel mode so we can drain messages sequentially
            logger.EnableChannelMode();

            // Simple console loop that periodically drains queued logs
            while (true)
            {
                while (logger.logChannel!.Reader.TryRead(out var log))
                {
                    AnsiConsole.MarkupLine(log.Format(logger.logType));
                }

                await Task.Delay(100);
            }
        }
    }
}
