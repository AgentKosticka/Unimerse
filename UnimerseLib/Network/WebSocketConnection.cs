using System;
using System.Buffers;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using UnimerseLib;

namespace UnimerseLib.Network
{
    /// <summary>
    /// Lightweight wrapper around client/server WebSocket operations that hides platform-specific details
    /// and provides symmetric helper methods for sending and receiving binary payloads.
    /// </summary>
    public sealed class WebSocketConnection : IDisposable
    {
        private readonly WebSocket socket;
        private readonly bool isClient;
        private readonly SemaphoreSlim sendLock = new(1, 1);
        private bool disposed;
        private bool sentClose;

        private WebSocketConnection(WebSocket socket, bool isClient, EndPoint? remoteEndPoint)
        {
            this.socket = socket;
            this.isClient = isClient;
            RemoteEndPoint = remoteEndPoint;
        }

        /// <summary>
        /// Remote endpoint associated with this logical connection when available.
        /// </summary>
        public EndPoint? RemoteEndPoint { get; }

        /// <summary>
        /// Current socket state exposed for diagnostics.
        /// </summary>
        public WebSocketState State => socket.State;

        /// <summary>
        /// Accepts an incoming ASP.NET Core WebSocket upgrade request and wraps the resulting socket.
        /// </summary>
        public static async Task<WebSocketConnection> AcceptAsync(HttpContext context, CancellationToken token, Logger? logger = null)
        {
            token.ThrowIfCancellationRequested();

            if (!context.WebSockets.IsWebSocketRequest)
            {
                throw new NonWebSocketRequestException("Incoming request did not include a WebSocket upgrade header.");
            }

            var socket = await context.WebSockets.AcceptWebSocketAsync();
            logger?.LogMessage(new Log("WebSocket handshake established", prefix: "WS", logLevel: LogLevel.Debug));

            EndPoint? remote = null;
            if (context.Connection.RemoteIpAddress != null)
            {
                remote = new IPEndPoint(context.Connection.RemoteIpAddress, context.Connection.RemotePort);
            }

            return new WebSocketConnection(socket, isClient: false, remote);
        }

        /// <summary>
        /// Establishes an outbound WebSocket connection to the specified host/path, optionally using TLS.
        /// </summary>
        public static async Task<WebSocketConnection> ConnectAsync(
            string host,
            int port,
            string path,
            CancellationToken token,
            Logger? logger = null,
            bool useTls = false,
            RemoteCertificateValidationCallback? certificateValidator = null,
            SslClientAuthenticationOptions? sslOptions = null)
        {
            var uriBuilder = new UriBuilder
            {
                Scheme = useTls ? "wss" : "ws",
                Host = host,
                Port = port,
                Path = path.StartsWith('/') ? path : "/" + path
            };

            ClientWebSocket client = new();
            if (certificateValidator != null)
            {
                client.Options.RemoteCertificateValidationCallback = certificateValidator;
            }

            if (sslOptions?.ClientCertificates != null)
            {
                foreach (X509Certificate certificate in sslOptions.ClientCertificates)
                {
                    client.Options.ClientCertificates.Add(certificate);
                }
            }

            await client.ConnectAsync(uriBuilder.Uri, token).ConfigureAwait(false);
            logger?.LogMessage(new Log("WebSocket handshake complete", prefix: "WS", logLevel: LogLevel.Debug));
            return new WebSocketConnection(client, isClient: true, new DnsEndPoint(host, port));
        }

        /// <summary>
        /// Reads frames until a complete message is assembled or the connection is closed.
        /// Returns <c>null</c> when a close handshake is observed.
        /// </summary>
        public async Task<byte[]?> ReceiveAsync(CancellationToken token)
        {
            ObjectDisposedException.ThrowIf(disposed, nameof(WebSocketConnection));

            byte[] buffer = ArrayPool<byte>.Shared.Rent(16 * 1024);
            try
            {
                using MemoryStream messageBuffer = new();
                while (true)
                {
                    var segment = new ArraySegment<byte>(buffer);
                    WebSocketReceiveResult result = await socket.ReceiveAsync(segment, token).ConfigureAwait(false);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await HandleCloseFrameAsync(token).ConfigureAwait(false);
                        return null;
                    }

                    if (result.Count > 0)
                    {
                        messageBuffer.Write(buffer, 0, result.Count);
                    }

                    if (result.EndOfMessage)
                    {
                        return messageBuffer.ToArray();
                    }

                    if (socket.State != WebSocketState.Open && socket.State != WebSocketState.CloseReceived)
                    {
                        return null;
                    }
                }
            }
            catch (WebSocketException)
            {
                return null;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return null;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        /// <summary>
        /// Sends a binary frame to the peer while ensuring serialized writes.
        /// </summary>
        public async Task SendBinaryAsync(ReadOnlyMemory<byte> payload, CancellationToken token)
        {
            ObjectDisposedException.ThrowIf(disposed, nameof(WebSocketConnection));

            if (socket.State != WebSocketState.Open && socket.State != WebSocketState.CloseReceived)
            {
                return;
            }

            await sendLock.WaitAsync(token).ConfigureAwait(false);
            try
            {
                if (socket.State != WebSocketState.Open && socket.State != WebSocketState.CloseReceived)
                {
                    return;
                }

                await socket.SendAsync(payload, WebSocketMessageType.Binary, endOfMessage: true, token).ConfigureAwait(false);
            }
            catch (WebSocketException) when (socket.State is WebSocketState.Aborted or WebSocketState.Closed)
            {
                // Peer disconnected or the socket was aborted; treat as a no-op send.
            }
            finally
            {
                sendLock.Release();
            }
        }

        /// <summary>
        /// Initiates a close handshake if one has not already been sent or observed.
        /// </summary>
        public async Task CloseAsync(CancellationToken token)
        {
            if (disposed || sentClose)
            {
                return;
            }

            sentClose = true;

            if (socket.State == WebSocketState.Open || socket.State == WebSocketState.CloseReceived)
            {
                try
                {
                    await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", token).ConfigureAwait(false);
                }
                catch
                {
                    // ignore
                }
            }
        }

        /// <summary>
        /// Releases the underlying WebSocket and associated resources.
        /// </summary>
        public void Dispose()
        {
            if (disposed)
            {
                return;
            }

            disposed = true;

            try
            {
                socket.Abort();
                socket.Dispose();
            }
            catch
            {
                // best effort
            }
            finally
            {
                sendLock.Dispose();
            }
        }

        /// <summary>
        /// Mirrors a received close frame to complete the WebSocket closing handshake.
        /// </summary>
        private async Task HandleCloseFrameAsync(CancellationToken token)
        {
            if (sentClose)
            {
                return;
            }

            sentClose = true;

            if (socket.State == WebSocketState.CloseReceived)
            {
                try
                {
                    if (isClient)
                    {
                        await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "Closing", token).ConfigureAwait(false);
                    }
                    else
                    {
                        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", token).ConfigureAwait(false);
                    }
                }
                catch
                {
                    // ignore cleanup errors
                }
            }
        }
    }

    internal sealed class NonWebSocketRequestException(string message) : Exception(message) { }
}
