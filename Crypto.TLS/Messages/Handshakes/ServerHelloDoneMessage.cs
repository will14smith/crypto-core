using Crypto.Utils;
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

        public static ServerHelloDoneMessage Read(byte[] body)
        {
            SecurityAssert.Assert(body.Length == 0);
            
            return new ServerHelloDoneMessage();
        }
    }
}