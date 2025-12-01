using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using System;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;
using UnimerseLib.Cryptography;

namespace UnimerseLib.Network
{
    /// <summary>
    /// Hosts the server-side transport pipeline, exposing HTTP diagnostics routes and a WebSocket endpoint
    /// that performs key exchange, authentication, and message broadcasting.
    /// </summary>
    public class ServerCommunicator : NetworkCommunicator, IDisposable
    {
        /// <summary>
        /// Represents a connected client along with its cipher state.
        /// </summary>
        public record ClientInfo(WebSocketConnection Connection, Cipher Cipher, string Name);

        private WebApplication? app;
        private Task? appTask;
        /// <summary>
        /// Collection of currently connected clients.
        /// </summary>
        public List<ClientInfo> ConnectedClients { get; } = [];
        private readonly Lock connectedClientsLock = new();

        public string description = "A default Unimerse server";

        public override bool IsServer => true;

        /// <summary>
        /// Raised when a client completes the handshake and is added to the roster.
        /// </summary>
        public event Action<ClientInfo>? ClientConnected;
        /// <summary>
        /// Raised when a client disconnects and is removed from the roster.
        /// </summary>
        public event Action<ClientInfo>? ClientDisconnected;

        private protected virtual void OnClientConnected(ClientInfo ci) => ClientConnected?.Invoke(ci);
        private protected virtual void OnClientDisconnected(ClientInfo ci) => ClientDisconnected?.Invoke(ci);

        /// <summary>
        /// Spins up a minimal Kestrel pipeline bound to the provided port and begins processing requests.
        /// </summary>
        public Task StartServerAsync(int port)
        {
            if (app != null)
            {
                throw new InvalidOperationException("Server already started.");
            }

            var builder = WebApplication.CreateSlimBuilder();
            builder.WebHost.ConfigureKestrel(options => options.ListenAnyIP(port));

            var webApp = builder.Build();

            webApp.UseWebSockets(new WebSocketOptions
            {
                KeepAliveInterval = TimeSpan.FromSeconds(30)
            });

            var staticPath = Path.Combine(Directory.GetCurrentDirectory(), "staticwebroot");

            webApp.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new PhysicalFileProvider(staticPath)
            });
            webApp.MapGet("/", async context =>
            {
                context.Response.ContentType = "text/html; charset=utf-8";
                await context.Response.SendFileAsync(Path.Combine(staticPath, "index.html"), cts.Token);
            });

            webApp.MapGet("/isvalidunimerseserver", async context =>
            {
                context.Response.ContentType = "text/plain";
                context.Response.StatusCode = StatusCodes.Status200OK;
                await context.Response.WriteAsync("OK/UNIMERSESERVER");
            });
            webApp.Map("/chat", HandleWebSocketEndpointAsync);

            webApp.MapGet("/favicon.ico", async context =>
            {
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                await Task.CompletedTask;
            });

            webApp.MapFallback(WriteErrorPage);

            app = webApp;
            appTask = webApp.RunAsync(cts.Token);

            LogMessage($"Listening for HTTP/WebSocket connections on port {port}");

            return Task.CompletedTask;
        }

        /// <summary>
        /// Returns a simple HTML landing page summarizing the instance and available endpoints.
        /// </summary>
        private Task WriteErrorPage(HttpContext context)
        {
            string html = $"<!DOCTYPE html><html><head><meta charset=\"utf-8\" />" +
                "<title>Unimerse Server</title></head><body>" +
                "<h1>Unimerse Server Error</h1>" +
                $"<p>It looks like you accessed an invalid page at {context.Request.Path}. This page doesn't exist</p>" +
                "<p>The WebSocket endpoint is available at <code>/chat</code>.</p>" +
                "</body></html>";

            context.Response.ContentType = "text/html; charset=utf-8";
            return context.Response.WriteAsync(html);
        }

        /// <summary>
        /// Validates upgrade requests targeting <c>/chat</c> and forwards them to the connection handler.
        /// </summary>
        private Task HandleWebSocketEndpointAsync(HttpContext context)
        {
            if (!context.WebSockets.IsWebSocketRequest)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return context.Response.WriteAsync("Expected WebSocket upgrade.");
            }

            return HandleWebSocketClientAsync(context);
        }

        /// <summary>
        /// Executes the secure handshake pipeline for a single client, tracks lifecycle, and relays packets.
        /// </summary>
        private async Task HandleWebSocketClientAsync(HttpContext context)
        {
            ClientInfo? clientInfo = null;
            WebSocketConnection? socket = null;
            Cipher cipher = new(storeRSAKey: true);

            try
            {
                socket = await WebSocketConnection.AcceptAsync(context, cts.Token, logger);
                LogMessage(new Log($"Client connected: {socket.RemoteEndPoint}", logLevel: LogLevel.Debug));

                var keys = await ReceivePacketAsync(socket, null, expectUnencryptedPacket: true);
                if (keys == null)
                {
                    LogMessage(new Log("Client disconnected before sending public keys", logLevel: LogLevel.Debug));
                    return;
                }

                if (keys is not PublicKeysExchangePacket pkep)
                {
                    await SendPacketAsync(new StatusPacket { Code = 21 }, socket, cipher, sendUnencryptedPacket: true);
                    LogMessage($"Client rejected (invalid key exchange): {socket.RemoteEndPoint}", logLevel: LogLevel.Warning);
                    return;
                }

                LogMessage(new Log("Received public keys", logLevel: LogLevel.Debug));

                cipher.SetPeerPublicKeys(pkep.RSAPublicKey, pkep.ECDHPublicKey, pkep.ECDHSignature);

                var serverKeys = new PublicKeysExchangePacket
                {
                    RSAPublicKey = Cipher.RSAPublicKey,
                    ECDHPublicKey = cipher.ECDHPublicKey,
                    ECDHSignature = cipher.ECDHSignature
                };
                await SendPacketAsync(serverKeys, socket, cipher, sendUnencryptedPacket: true);

                LogMessage(new Log("Sent public keys", logLevel: LogLevel.Debug));

                Packet? handshake = await ReceivePacketAsync(socket, cipher);
                if (handshake == null)
                {
                    LogMessage(new Log("Client disconnected during auth handshake", logLevel: LogLevel.Debug));
                    return;
                }

                if (handshake is not AuthPacket auth || auth.Token != sharedSecret || auth.Username.Contains('[') || auth.Username.Contains(']'))
                {
                    await SendPacketAsync(new StatusPacket { Code = 21 }, socket, cipher);
                    LogMessage($"Client rejected (invalid auth): {socket.RemoteEndPoint}", logLevel: LogLevel.Warning);
                    return;
                }

                LogMessage(new Log($"Auth done (username: {auth.Username})", logLevel: LogLevel.Debug));

                bool nameInUse;
                lock (connectedClientsLock)
                {
                    nameInUse = ConnectedClients.Any(c => c.Name == auth.Username);
                }

                LogMessage(nameInUse ?
                    $"Client {auth.Username}: {socket.RemoteEndPoint} rejected (username in use)" :
                    $"Client authenticated: {auth.Username} from {socket.RemoteEndPoint}",
                    logLevel: LogLevel.Required);

                if (nameInUse)
                {
                    await SendPacketAsync(new StatusPacket { Code = 23 }, socket, cipher);
                    return;
                }

                clientInfo = new ClientInfo(socket, cipher, auth.Username);

                lock (connectedClientsLock)
                {
                    ConnectedClients.Add(clientInfo);
                }

                await SendPacketAsync(new StatusPacket { Code = 10 }, clientInfo);
                OnClientConnected(clientInfo);

                await SendBrodcastPacketAsync(new ClientJoinedPacket { Username = auth.Username });

                await SendPacketAsync(new ServerStatusPacket { CurrentUsers = [.. ConnectedClients.Select(c => c.Name)], Description = description }, clientInfo);

                await ReceiveLoopAsync(socket, cipher);
            }
            catch (NonWebSocketRequestException ex)
            {
                LogMessage(new Log(ex.Message, logLevel: LogLevel.Debug));
            }
            catch (WebSocketException ex)
            {
                LogMessage(new Log($"WebSocket error: {ex.Message}", logLevel: LogLevel.Debug));
            }
            catch (Exception ex)
            {
                OnError(ex);
            }
            finally
            {
                if (clientInfo != null)
                {
                    await SendBrodcastPacketAsync(new ClientLeftPacket { Username = clientInfo.Name });
                    OnClientDisconnected(clientInfo);

                    lock (connectedClientsLock)
                    {
                        var client = ConnectedClients.FirstOrDefault(c => c.Name == clientInfo.Name);
                        if (client != null)
                        {
                            ConnectedClients.Remove(client);
                        }
                    }
                }

                socket?.Dispose();
                cipher.Dispose();
            }
        }

        /// <summary>
        /// Encrypts and delivers a packet to a specific connected client.
        /// </summary>
        public Task SendPacketAsync(Packet p, ClientInfo c, bool sendUnencryptedPacket = false)
        {
            ArgumentNullException.ThrowIfNull(c);

            return SendPacketAsync(p, c.Connection, c.Cipher, sendUnencryptedPacket);
        }

        /// <summary>
        /// Core packet send routine that serializes payloads through the provided connection.
        /// </summary>
        public Task SendPacketAsync(Packet p, WebSocketConnection socket, Cipher cipher, bool sendUnencryptedPacket = false)
        {
            ArgumentNullException.ThrowIfNull(socket);

            byte[] buf = p.Serialize();

            if (!sendUnencryptedPacket)
            {
                buf = cipher.Encrypt(buf);
            }

            return socket.SendBinaryAsync(buf, cts.Token);
        }

        /// <summary>
        /// Issues a packet to every currently connected client in parallel.
        /// </summary>
        public Task SendBrodcastPacketAsync(Packet p)
        {
            List<Task> tasks = [];
            lock (connectedClientsLock)
            {
                foreach (var c in ConnectedClients)
                {
                    tasks.Add(SendPacketAsync(p, c));
                }
            }

            return Task.WhenAll(tasks);
        }

        /// <inheritdoc/>
        public override Task HandlePacketResponseAsync(PacketResponse pr)
        {
            ServerPacketResponse svr = (ServerPacketResponse)pr;
            if (svr.isBrodcast)
            {
                return SendBrodcastPacketAsync(svr.packet);
            }
            else if (svr.respondTo != null)
            {
                var client = ConnectedClients.Find(ci => ReferenceEquals(ci.Connection, svr.respondTo));
                if (client != null)
                {
                    return SendPacketAsync(svr.packet!, client);
                }

                throw new Exception("Client not found");
            }

            throw new Exception("No target specified for packet response");
        }

        /// <inheritdoc/>
        public override void Dispose()
        {
            cts.Cancel();

            if (app != null)
            {
                try
                {
                    using CancellationTokenSource stopCts = new(TimeSpan.FromSeconds(5));
                    app.StopAsync(stopCts.Token).GetAwaiter().GetResult();
                }
                catch
                {
                }
                finally
                {
                    app.DisposeAsync().AsTask().GetAwaiter().GetResult();
                    app = null;
                }
            }

            if (appTask != null)
            {
                try
                {
                    appTask.GetAwaiter().GetResult();
                }
                catch (OperationCanceledException)
                {
                }
                catch (Exception ex)
                {
                    OnError(ex);
                }
                finally
                {
                    appTask = null;
                }
            }

            connectedClientsLock.Enter();
            foreach (var c in ConnectedClients)
            {
                c.Connection.Dispose();
                c.Cipher.Dispose();
            }
            ConnectedClients.Clear();
            connectedClientsLock.Exit();

            base.Dispose();

            GC.SuppressFinalize(this);
        }
    }
}
