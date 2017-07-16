using System;
using System.Collections.Generic;
using Crypto.Certificates;
using Crypto.RSA.Keys;
using Crypto.TLS.KeyExchange;
using Crypto.TLS.Messages.Handshakes;

namespace Crypto.TLS.EC
{
    public class ECDHEKeyExchange : IKeyExchange
    {
        public bool IsCompatible(CipherSuite cipherSuite, X509Certificate certificate)
        {
            // TODO check cipherSuite == ECDSA/ESA
            // cert has RSA public key
            if (!(certificate.SubjectPublicKey is RSAPublicKey))
            {
                return false;
            }

            // TODO ?
            return true;
        }

        public IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            throw new NotImplementedException();
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            throw new NotImplementedException();
        }
    }
}
