using System.IO;
using Crypto.TLS.Records;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public abstract class HandshakeMessage : IMessage
    {
        public RecordType Type => RecordType.Handshake;

        protected HandshakeMessage(HandshakeType handshakeType)
        {
            HandshakeType = handshakeType;
        }

        public HandshakeType HandshakeType { get; }

        public byte[] GetBytes()
        {
            using (var ms = new MemoryStream())
            {
                var writer = new EndianBinaryWriter(EndianBitConverter.Big, ms);

                writer.Write(HandshakeType);
                writer.WriteUInt24(0);

                Write(writer);

                writer.Seek(1, SeekOrigin.Begin);
                writer.WriteUInt24((uint)ms.Length - 4);

                return ms.ToArray();
            }
        }

        protected abstract void Write(EndianBinaryWriter writer);

    }
}
