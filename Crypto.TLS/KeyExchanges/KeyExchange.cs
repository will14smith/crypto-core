using System.Collections.Generic;
using Crypto.Certificates;
using Crypto.TLS.Messages.Handshakes;

namespace Crypto.TLS.KeyExchanges
{
    public abstract class KeyExchange : IKeyExchange
    {
        private readonly IServerKeyExchange _server;
        private readonly IClientKeyExchange _client;

        protected KeyExchange(IServerKeyExchange server, IClientKeyExchange client)
        {
            _server = server;
            _client = client;
        }

        public abstract bool IsCompatible(CipherSuite cipherSuite, X509Certificate certificate);

        public virtual IEnumerable<HandshakeMessage> GenerateServerHandshakeMessages()
        {
            return _server.GenerateServerHandshakeMessages();
        }

        public virtual void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            _server.HandleClientKeyExchange(message);
        }

        public virtual void HandleServerKeyExchange(ServerKeyExchangeMessage message)
        {
            _client.HandleServerKeyExchange(message);
        }

        public virtual IEnumerable<HandshakeMessage> GenerateClientHandshakeMessages()
        {
            return _client.GenerateClientHandshakeMessages();
        }
    }
}
