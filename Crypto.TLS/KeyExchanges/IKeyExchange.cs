using System.Collections.Generic;
using Crypto.Certificates;
using Crypto.TLS.Messages.Handshakes;

namespace Crypto.TLS.KeyExchanges
{
    public interface IKeyExchange : IServerKeyExchange, IClientKeyExchange
    {
        bool IsCompatible(CipherSuite cipherSuite, X509Certificate certificate);
    }

    public interface IServerKeyExchange
    {
        IEnumerable<HandshakeMessage> GenerateServerHandshakeMessages();
        void HandleClientKeyExchange(ClientKeyExchangeMessage message);
    }
    
    public interface IClientKeyExchange
    {
        void HandleServerKeyExchange(ServerKeyExchangeMessage message);
        IEnumerable<HandshakeMessage> GenerateClientHandshakeMessages();
    }
}
