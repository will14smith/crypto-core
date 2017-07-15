using System;
using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public class ClientKeyExchangeMessage : HandshakeMessage
    {
        public byte[] Body { get; }

        public ClientKeyExchangeMessage(byte[] body) 
            : base(HandshakeType.ClientKeyExchange)
        {
            Body = body;
        }

        protected override void Write(EndianBinaryWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}
