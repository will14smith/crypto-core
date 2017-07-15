using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public class ServerHelloDoneMessage : HandshakeMessage
    {
        public ServerHelloDoneMessage() : base(HandshakeType.ServerHelloDone)
        {
        }

        protected override void Write(EndianBinaryWriter writer)
        {
        }
    }
}