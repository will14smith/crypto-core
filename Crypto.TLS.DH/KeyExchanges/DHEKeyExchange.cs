using Crypto.Certificates;
using Crypto.RSA.Keys;
using Crypto.TLS.Config;
using Crypto.TLS.KeyExchanges;

namespace Crypto.TLS.DH.KeyExchanges
{
    public class DHEKeyExchange : KeyExchange
    {
        public DHEKeyExchange(DHEServerKeyExchange server, DHEClientKeyExchange client) : base(server, client)
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

            // TODO ?
            return true;
        }
    }
}
