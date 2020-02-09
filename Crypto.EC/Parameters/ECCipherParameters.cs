using Crypto.Core.Encryption.Parameters;
using Crypto.EC.Maths;

namespace Crypto.EC.Parameters
{
    public class ECCipherParameters : ICipherParameters
    {
        public DomainParameters Domain { get; }
        public ECPublicKey PublicKey { get; }
        public ECPrivateKey? PrivateKey { get; }

        public ECCipherParameters(DomainParameters domain, ECPublicKey publicKey)
        {
            Domain = domain;
            PublicKey = publicKey;
        }

        public ECCipherParameters(DomainParameters domain, ECPrivateKey privateKey)
        {
            Domain = domain;
            PublicKey = (ECPublicKey)privateKey.PublicKey;
            PrivateKey = privateKey;
        }
    }
}
