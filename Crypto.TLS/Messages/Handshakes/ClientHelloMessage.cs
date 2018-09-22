using System.Collections.Generic;
using System.IO;
using System.Linq;
using Crypto.TLS.Extensions;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public class ClientHelloMessage : HelloMessage
    {
        public ClientHelloMessage(TLSVersion version, byte[] randomBytes, byte[] sessionId, HelloExtension[] extensions, CipherSuite[] cipherSuites, CompressionMethod[] compressionMethods)
            : base(HandshakeType.ClientHello, version, randomBytes, sessionId, extensions)
        {
            SecurityAssert.NotNull(cipherSuites);
            SecurityAssert.Assert(cipherSuites.Length >= 1 && cipherSuites.Length <= 0x7FFF);
            CipherSuites = cipherSuites;

            SecurityAssert.NotNull(compressionMethods);
            SecurityAssert.Assert(compressionMethods.Length >= 1 && cipherSuites.Length <= 0xFF);
            CompressionMethods = compressionMethods;
        }

        public CipherSuite[] CipherSuites { get; }
        public CompressionMethod[] CompressionMethods { get; }

        protected override void WriteHello(EndianBinaryWriter writer)
        {
            writer.WriteUInt16Variable(2, CipherSuites);
            writer.WriteByteVariable(1, CompressionMethods);
        }

        internal static ClientHelloMessage Read(byte[] body)
        {
            using (var stream = new MemoryStream(body))
            {
                var reader = new EndianBinaryReader(EndianBitConverter.Big, stream);

                var version = reader.ReadVersion();
                var randomBytes = reader.ReadBytes(32);
                var sessionId = reader.ReadBytesVariable(1, 0, 32);

                var cipherSuites = reader.ReadUInt16Variable<CipherSuite>(2, 1, 0x7FFF);
                var compressionMethods = reader.ReadBytesVariable<CompressionMethod>(1, 1, 0xFF).ToArray();

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

                return new ClientHelloMessage(version, randomBytes, sessionId, extensions.ToArray(), cipherSuites, compressionMethods);
            }
        }
    }
}
