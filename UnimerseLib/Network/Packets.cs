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
    public abstract class Packet
    {
        public abstract byte ID { get; }
        public long Timestamp { get; set; }
        public override string ToString() => $"{GetType().Name} (ID: {ID:X2})";
        protected Packet()
        {
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        private static readonly Dictionary<byte, Type> packetTypes = Assembly.GetExecutingAssembly()
            .GetTypes()
            .Where(t => t.IsSubclassOf(typeof(Packet)) && !t.IsAbstract)
            .ToDictionary(
                t => (byte)((Packet)Activator.CreateInstance(t)!).ID,
                t => t
            );

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

    public class PublicKeysExchangePacket : Packet
    {
        public override byte ID => 0xf0;
        public byte[] RSAPublicKey { get; set; } = [];
        public byte[] ECDHPublicKey { get; set; } = [];
        public byte[] ECDHSignature { get; set; } = [];
    }

    public class AuthPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0xf1;
        public string Token { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
    }

    public class ClientJoinedPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0xf2;
        public string Username { get; set; } = string.Empty;
    }
    public class ClientLeftPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0xf3;
        public string Username { get; set; } = string.Empty;
    }
    public class ServerStatusPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0xf4;
        public string[] CurrentUsers { get; set; } = [];
        public string Description { get; set; } = string.Empty;
    }
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

    public class ChatPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0x02;
        public string Message { get; set; } = string.Empty;
    }

    public class ChatBrodcastPacket : Packet
    {
        [JsonIgnore]
        public override byte ID => 0x03;
        public string Sender { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }
}

