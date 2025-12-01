using System;

namespace UnimerseLib.Network
{
    /// <summary>
    /// Captures the outcome of handling a received packet, including optional response data.
    /// </summary>
    public abstract class PacketResponse
    {
        public Packet packet = new StatusPacket() { Code = 10 };
        public bool canceled = false;
        public void Cancel() => canceled = true;

        /// <summary>
        /// Initializes a new instance of the <see cref="PacketResponse"/> class with a default status packet.
        /// </summary>
        public PacketResponse() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="PacketResponse"/> class using the provided packet.
        /// </summary>
        public PacketResponse(Packet p)
        {
            packet = p;
        }
    }

    /// <summary>
    /// Response context used on the server to optionally target a specific client.
    /// </summary>
    public class ServerPacketResponse(WebSocketConnection? respondTo = null) : PacketResponse
    {
        /// <summary>
        /// Gets or sets a value indicating whether the response should be broadcast to all clients.
        /// </summary>
        public bool isBrodcast = false;
        /// <summary>
        /// Connection to reply to when a broadcast is not requested.
        /// </summary>
        public WebSocketConnection? respondTo = respondTo;
    }

    /// <summary>
    /// Response context used on the client when handling server packets.
    /// </summary>
    public class ClientPacketResponse : PacketResponse
    { }
}
