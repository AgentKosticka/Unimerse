using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using UnimerseLib.Network;
using Spectre.Console;
using System.Threading.Channels;
using UnimerseLib;
using System.Reflection.Emit;

namespace UnimerseClient
{
    public class Program
    {
        const int ListenTimeoutMs = 5000; // listen window
        const string SharedSecret = "unimerse-rocks"; // must match server
        static string Username = "Laptop"; // username to send to server
        const string LogPrefix = "Client"; // log prefix
        const string Style = "springgreen3"; // client message style

        public readonly static Logger logger = new(LogPrefix, Style);

        static async Task Main()
        {
            // Ensure UTF-8 console
            Console.InputEncoding = Encoding.UTF8;
            Console.OutputEncoding = Encoding.UTF8;

            logger.acceptedLevel = LogLevel.Debug;

            AnsiConsole.Write(new FigletText("Unimerse").Centered().Color(Color.IndianRed));
            AnsiConsole.Write(new FigletText("Client").Centered().Color(Color.SpringGreen3));
            AnsiConsole.Write("\n");

            Username = AnsiConsole.Ask<string>(logger.Format("Please set your username:"));

            using ClientCommunicator comm = new();
            comm.sharedSecret = SharedSecret;
            comm.logger = logger;
            comm.Error += (ex) =>
            {
                logger.LogMessage(new Log($"Network error: {ex.Message}", logLevel: LogLevel.Error));
                logger.logChannel?.Writer.Complete();
            };

            comm.Initialize();

            //var endpoint = new ClientCommunicator.ServerEndpoint("api.anthe.win", 443, "/chat", true);
            var endpoint = new ClientCommunicator.ServerEndpoint("localhost", 5000, "/chat", false);

            bool endpointAccessible = comm.VerifyEndpointAccessible(endpoint, ListenTimeoutMs).GetAwaiter().GetResult();

            if (!endpointAccessible)
            {
                logger.LogMessage(new Log($"Cannot reach server at {(endpoint.UseTls ? "wss" : "ws")}://{endpoint.Host}:{endpoint.Port}{endpoint.Path}", logLevel: LogLevel.Error));
                logger.LogMessage(new Log($"The server didn't answer the way a Unimerse server should", logLevel: LogLevel.Error));
                return;
            }
            else
            {
                logger.LogMessage(new Log($"Server at {(endpoint.UseTls ? "wss" : "ws")}://{endpoint.Host}:{endpoint.Port}{endpoint.Path} is accessible, connecting", logLevel: LogLevel.Info));
            }

                comm.PacketReceived += (p, response, source) =>
                {
                    ClientPacketResponse cpr = (ClientPacketResponse)response;

                    switch (p)
                    {
                        case StatusPacket sp when sp.Code == 10:
                            cpr.Cancel();
                            break;
                        case ClientJoinedPacket cjp:
                            logger.LogMessage(new Log($"{cjp.Username} joined the chat.", style: "springgreen3", logLevel: LogLevel.Required));
                            cpr.Cancel();
                            break;
                        case ClientLeftPacket clp:
                            logger.LogMessage(new Log($"{clp.Username} left the chat.", style: "springgreen3", logLevel: LogLevel.Required));
                            cpr.Cancel();
                            break;
                        case ServerStatusPacket ssp:
                            logger.LogMessage(new Log($"Server description: {ssp.Description}", logLevel: LogLevel.Required));
                            logger.LogMessage(new Log($"Current users ({ssp.CurrentUsers.Length}): {string.Join(", ", ssp.CurrentUsers)}", logLevel: LogLevel.Required));
                            break;

                        case ChatBrodcastPacket cbp:
                            logger.LogMessage(new Log(cbp.Message, prefix: cbp.Sender, style: "springgreen3", logLevel: LogLevel.Required));
                            break;
                        default:
                            logger.LogMessage(new Log($"Received unknown packet type {p.GetType().Name}: {p.ID} from server.", logLevel: LogLevel.Error));
                            cpr.Cancel();
                            break;
                    }
                };

            try
            {
                logger.LogMessage(new Log($"Connecting to {(endpoint.UseTls ? "wss" : "ws")}://{endpoint.Host}:{endpoint.Port}{endpoint.Path}", logLevel: LogLevel.Info));
                comm.ConnectAsync(endpoint, Username).GetAwaiter().GetResult();
                AnsiConsole.Markup("Connected, type:");

                StringBuilder inputBuffer = new();
                List<Log> messages = [];

                // Theese two bools are done so the last render doesnt have the input line
                bool completed = false;
                bool running = true;


                logger.EnableChannelMode();

                // Start UI loop
                _ = AnsiConsole.Live(new Markup("")).StartAsync(async ctx =>
                {
                    while (running)
                    {
                        while (logger.logChannel!.Reader.TryRead(out var log))
                        {
                            messages.Add(log);
                        }

                        StringBuilder display = new();
                        display.AppendLine(logger.Format($"Now you can chat freely"));

                        foreach (Log log in messages)
                        {
                            display.AppendLine(log.Format(logger.logType));
                        }

                        if (!completed)
                        {
                            display.Append(logger.Format(Markup.Escape(inputBuffer.ToString()) + "[rapidblink grey]|[/]", style: "sandybrown", prefix: ">", brackets: false));
                        }
                        else
                        {
                            running = false;
                        }

                        ctx.UpdateTarget(new Markup(display.ToString()));

                        // Handle user input
                        if (Console.KeyAvailable)
                        {
                            var key = Console.ReadKey(intercept: true);
                            if (key.Key == ConsoleKey.Enter)
                            {
                                var line = inputBuffer.ToString();
                                inputBuffer.Clear();

                                //messages.Add(lg.Format(Markup.Escape(line)));

                                var chatPacket = new ChatPacket { Message = line };
                                comm.SendPacketAsync(chatPacket).GetAwaiter().GetResult();
                            }
                            else if (key.Key == ConsoleKey.Backspace && inputBuffer.Length > 0)
                            {
                                inputBuffer.Length--;
                            }
                            else if (!char.IsControl(key.KeyChar))
                            {
                                inputBuffer.Append(key.KeyChar);
                            }
                        }

                        await Task.Delay(1);
                    }
                });

                // Wait for being disconnected
                await logger.logChannel!.Reader.Completion;
                completed = true;

                Console.ReadKey(true);
            }
            catch (Exception ex)
            {
                logger.DisableChannelMode();
                logger.LogMessage(new Log($"Error: {ex.Message}", logLevel: LogLevel.Error));
            }
        }
    }
}
