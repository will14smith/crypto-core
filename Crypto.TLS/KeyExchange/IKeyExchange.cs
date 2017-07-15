using System.Collections.Generic;
using Crypto.TLS.Messages.Handshakes;

namespace Crypto.TLS.KeyExchange
{
    public interface IKeyExchange
    {
        IEnumerable<HandshakeMessage> GenerateHandshakeMessages();

        void HandleClientKeyExchange(ClientKeyExchangeMessage message);
    }
}
