using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public static class EndianBinaryReaderExtensions
    {
        public static HandshakeType ReadHandshakeType(this EndianBinaryReader reader)
        {
            return (HandshakeType)reader.ReadByte();
        }
    }
}
