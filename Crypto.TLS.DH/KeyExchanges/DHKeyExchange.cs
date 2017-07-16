using System.Numerics;
using Crypto.Certificates;
using Crypto.TLS.Config;
using Crypto.TLS.DH.Keys;
using Crypto.TLS.KeyExchange;
using Crypto.Utils;

namespace Crypto.TLS.DH.KeyExchanges
{
    public class DHKeyExchange : DHKeyExchangeBase
    {
        private readonly CertificateManager _certificateManager;

        public DHKeyExchange(
            CertificateManager certificateManager,
            MasterSecretCalculator masterSecretCalculator,

            CertificateConfig certificateConfig)
                : base(masterSecretCalculator, certificateConfig)
        {
            _certificateManager = certificateManager;
        }

        public override BigInteger CalculatedSharedSecret(BigInteger yc)
        {
            var key = GetPrivateKey();
            
            return BigInteger.ModPow(yc, key.X, key.DHPublicKey.P);
        }
        
        private DHPrivateKey GetPrivateKey()
        {
            var cert = CertificateConfig.Certificate;
            var key = _certificateManager.GetPrivateKey(cert.SubjectPublicKey);

            var dhKey = key as DHPrivateKey;
            SecurityAssert.NotNull(dhKey);

            return dhKey;
        }
    }
}
