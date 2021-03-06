﻿using Crypto.Certificates;
using Crypto.RSA.Keys;
using Crypto.TLS.DH.Keys;
using Crypto.TLS.KeyExchanges;

namespace Crypto.TLS.DH.KeyExchanges
{
    public class DHKeyExchange : KeyExchange
    {
        public DHKeyExchange(DHServerKeyExchange server, DHClientKeyExchange client) 
            : base(server, client)
        {
        }

        public override bool IsCompatible(CipherSuite cipherSuite, X509Certificate certificate)
        {
            // TODO check cipherSuite == RSA/DSS
            // cert signed with RSA
            if (!RSAKeyReader.IsRSAIdentifier(certificate.SignatureAlgorithm.Algorithm))
            {
                return false;
            }

            // cert has DH public key
            if (!(certificate.SubjectPublicKey is DHPublicKey))
            {
                return false;
            }

            // TODO ?
            return true;
        }
    }
}
