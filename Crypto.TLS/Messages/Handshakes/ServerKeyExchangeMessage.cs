using System.Collections.Generic;
using System.Linq;
using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public class ServerKeyExchangeMessage : HandshakeMessage
    {
        /// <summary>
        /// Opaque data from IKeyExchange implementation
        /// </summary>
        public IReadOnlyCollection<byte> Data { get; }

        public ServerKeyExchangeMessage(IReadOnlyCollection<byte> data) : base(HandshakeType.ServerKeyExchange)
        {
            Data = data;
        }

        protected override void Write(EndianBinaryWriter writer)
        {
            writer.Write(Data.ToArray());
        }
    }
}
