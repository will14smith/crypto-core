using System.Linq;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public abstract class HelloMessage : HandshakeMessage
    {
        protected HelloMessage(HandshakeType type, TLSVersion version, byte[] randomBytes, byte[] sessionId, HelloExtension[] extensions) : base(type)
        {
            Version = version;

            SecurityAssert.NotNull(randomBytes);
            SecurityAssert.Assert(randomBytes.Length == 32);
            RandomBytes = randomBytes;

            SecurityAssert.NotNull(sessionId);
            SecurityAssert.Assert(sessionId.Length >= 0 && sessionId.Length <= 32);
            SessionId = sessionId;

            SecurityAssert.NotNull(extensions);
            SecurityAssert.Assert(extensions.Length >= 0 && extensions.Length <= 0xFFFF);
            Extensions = extensions;
        }

        public TLSVersion Version { get; }
        public byte[] RandomBytes { get; }
        public byte[] SessionId { get; }

        public HelloExtension[] Extensions { get; }

        protected sealed override void Write(EndianBinaryWriter writer)
        {
            writer.Write(Version);
            writer.Write(RandomBytes);
            writer.WriteVariable(1, SessionId);
            WriteHello(writer);

            if (Extensions.Length == 0)
            {
                return;
            }
            
            var totalLength = Extensions.Sum(x => 4 + x.Data.Length);
            writer.Write((ushort)totalLength);
            
            foreach (var extension in Extensions)
            {
                writer.Write((ushort)extension.Type);
                writer.Write((ushort)extension.Data.Length);
                writer.Write(extension.Data);
            }
        }

        protected abstract void WriteHello(EndianBinaryWriter writer);
    }
}