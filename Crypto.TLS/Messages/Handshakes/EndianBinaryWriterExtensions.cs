using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public static class EndianBinaryWriterExtensions
    {
        public static void Write(this EndianBinaryWriter writer, HandshakeType value)
        {
            writer.Write((byte)value);
        }
    }
}