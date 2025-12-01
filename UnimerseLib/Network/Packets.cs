using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace UnimerseLib.Network
{

    /// <summary>
    /// Base type for all packets exchanged between clients and the server.
    /// </summary>
    public abstract class Packet
    {
        public abstract byte ID { get; }
        public long Timestamp { get; set; }

        /// <summary>
        /// Returns a formatted representation including the packet identifier.
        /// </summary>
        public override string ToString() => $"{GetType().Name} (ID: {ID:X2})";
        protected Packet()
        {
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Maps packet identifiers to their concrete types via reflection for deserialization.
        /// </summary>
        private static readonly Dictionary<byte, Type> packetTypes = Assembly.GetExecutingAssembly()
            .GetTypes()
            .Where(t => t.IsSubclassOf(typeof(Packet)) && !t.IsAbstract)
            .ToDictionary(
                t => (byte)((Packet)Activator.CreateInstance(t)!).ID,
                t => t
            );

        /// <summary>
        /// Serializes the packet to an unencrypted binary payload.
        /// </summary>
        public byte[] Serialize()
        {

            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            // Serialize the object (JSON here, could be binary).
            var jsonData = JsonSerializer.SerializeToUtf8Bytes(this, GetType());

            writer.Write(jsonData.Length + 1); // write length of data + 1 byte for ID

            // Write the packet ID.
            writer.Write(ID);
            writer.Write(jsonData);

            return ms.ToArray();
        }

        /// <summary>
        /// Deserializes an unencrypted packet from a binary payload.
        /// </summary>
        public static Packet? Deserialize(byte[] data)
        {
            using var ms = new MemoryStream(data);
            using var reader = new BinaryReader(ms);

            int length = reader.ReadInt32(); // Read length.

            // Read the packet ID first.
            byte id = reader.ReadByte();

            byte[] jsonData = reader.ReadBytes(length - 1);

            if (!packetTypes.TryGetValue(id, out Type? type))
            {
                throw new Exception($"Unknown packet ID: {id}");
            }

            return (Packet?)JsonSerializer.Deserialize(jsonData, type);
        }
    }

    /// <summary>
    /// Broadcast UDP payload used for local service discovery.
    /// </summary>
    public class UDPBrodcastPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0xf0;
        public string ServiceName { get; set; } = string.Empty;
        public string Ip { get; set; } = string.Empty;
        public int Port { get; set; }
    }

    /// <summary>
    /// Exchanges RSA and ECDH material during the encrypted session handshake.
    /// </summary>
    public class PublicKeysExchangePacket : Packet
    {
        public override byte ID => 0xf1;
        public byte[] RSAPublicKey { get; set; } = [];
        public byte[] ECDHPublicKey { get; set; } = [];
        public byte[] ECDHSignature { get; set; } = [];
    }

    /// <summary>
    /// Carries the client's authentication token and desired username.
    /// </summary>
    public class AuthPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0xf2;
        public string Token { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
    }

    /// <summary>
    /// Communicates standardized status codes between peers.
    /// </summary>
    public class StatusPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0x01;
        public byte Code { get; set; }
        /// <remarks>
        /// 10 = OK, 11 = Executed, 20 = Rejected by receiver, 21 = Invalid token, 22 = Invalid command,
        /// 23 = Invalid data, 30 = Error executing command.
        /// </remarks>
    }

    /// <summary>
    /// Notifies connected clients when a new participant joins the server.
    /// </summary>
    public class ClientJoinedPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0xe1;
        public string Username { get; set; } = string.Empty;
    }

    /// <summary>
    /// Alerts connected clients when a participant disconnects.
    /// </summary>
    public class ClientLeftPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0xe2;
        public string Username { get; set; } = string.Empty;
    }

    /// <summary>
    /// Carries a chat message from a client to the server.
    /// </summary>
    public class ChatPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0x02;
        public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// Broadcasts a chat message from the server to all clients.
    /// </summary>
    public class ChatBrodcastPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0x03;
        public string Sender { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// Provides a snapshot of the server state, including active users and the current description.
    /// </summary>
    public class ServerStatusPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0xe3;
        public string[] CurrentUsers { get; set; } = [];
        public string Description { get; set; } = string.Empty;
    }
}

