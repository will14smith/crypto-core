using System.Collections.Generic;
using System.IO;
using Crypto.TLS.Extensions;
using Crypto.Utils;
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

        public static ServerHelloMessage Read(byte[] body)
        {
            using (var stream = new MemoryStream(body))
            {
                var reader = new EndianBinaryReader(EndianBitConverter.Big, stream);

                var version = reader.ReadVersion();
                var randomBytes = reader.ReadBytes(32);
                var sessionId = reader.ReadBytesVariable(1, 0, 32);

                var cipherSuite = (CipherSuite)reader.ReadUInt16();
                var compressionMethod = (CompressionMethod)reader.ReadByte();

                var extensions = new List<HelloExtension>();

                // extensions don't have to be included
                if (stream.Length != stream.Position)
                {
                    var extsLength = reader.ReadUInt16();

                    while (extsLength > 0)
                    {
                        extsLength -= 4;

                        var extType = (ExtensionType)reader.ReadUInt16();
                        var extLength = reader.ReadUInt16();
                        extsLength -= extLength;

                        var extBuffer = reader.ReadBytes(extLength);

                        extensions.Add(new HelloExtension(extType, extBuffer));
                    }
                }

                return new ServerHelloMessage(version, randomBytes, sessionId, extensions.ToArray(), cipherSuite, compressionMethod);
            }
        }
    }
}