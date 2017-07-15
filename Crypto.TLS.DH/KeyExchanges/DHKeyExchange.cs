using System;
using System.Collections.Generic;
using Crypto.TLS.Config;
using Crypto.TLS.KeyExchange;
using Crypto.TLS.Messages.Handshakes;

namespace Crypto.TLS.DH.KeyExchanges
{
    public class DHKeyExchange : IKeyExchange
    {
        private readonly CertificateConfig _certificateConfig;

        public DHKeyExchange(CertificateConfig certificateConfig)
        {
            _certificateConfig = certificateConfig;
        }

        public IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            yield return new CertificateMessage(_certificateConfig.CertificateChain);
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            throw new NotImplementedException();
        }
    }
}
