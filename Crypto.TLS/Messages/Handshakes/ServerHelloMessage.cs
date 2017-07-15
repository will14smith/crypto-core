using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public class ServerHelloMessage : HelloMessage
    {
        public ServerHelloMessage(TLSVersion version, byte[] randomBytes, byte[] sessionId, HelloExtension[] extensions, CipherSuite cipherSuite, CompressionMethod compressionMethod)
            : base(HandshakeType.ServerHello, version, randomBytes, sessionId, extensions)
        {
            CipherSuite = cipherSuite;
            CompressionMethod = compressionMethod;
        }

        public CipherSuite CipherSuite { get; }
        public CompressionMethod CompressionMethod { get; }

        protected override void WriteHello(EndianBinaryWriter writer)
        {
            writer.Write(CipherSuite);
            writer.Write(CompressionMethod);
        }
    }
}