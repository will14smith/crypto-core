using System.Collections.Generic;
using Crypto.Certificates;
using Crypto.TLS.Messages.Handshakes;

namespace Crypto.TLS.KeyExchange
{
    public interface IKeyExchange
    {
        bool IsCompatible(CipherSuite cipherSuite, X509Certificate certificate);

        IEnumerable<HandshakeMessage> GenerateHandshakeMessages();

        void HandleClientKeyExchange(ClientKeyExchangeMessage message);
    }
}
