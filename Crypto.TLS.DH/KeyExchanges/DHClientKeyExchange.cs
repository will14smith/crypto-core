using System;
using System.Collections.Generic;
using Crypto.TLS.KeyExchanges;
using Crypto.TLS.Messages.Handshakes;

namespace Crypto.TLS.DH.KeyExchanges
{
    public class DHClientKeyExchange : IClientKeyExchange
    {
        public void HandleServerKeyExchange(ServerKeyExchangeMessage message)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<HandshakeMessage> GenerateClientHandshakeMessages()
        {
            throw new NotImplementedException();
        }
    }
}