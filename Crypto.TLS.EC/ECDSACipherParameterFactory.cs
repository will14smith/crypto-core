using System;
using Crypto.Certificates;
using Crypto.Core.Encryption.Parameters;
using Crypto.EC.Parameters;
using Crypto.TLS.Config;
using Crypto.TLS.Services;
using Crypto.TLS.Suites.Parameters;

namespace Crypto.TLS.EC
{
    public class ECDSACipherParameterFactory : ICipherParameterFactory
    {
        private readonly CertificateManager _certificateManager;
        private readonly CertificateConfig _certificateConfig;

        public ECDSACipherParameterFactory(
            CertificateManager certificateManager,
            CertificateConfig certificateConfig)
        {
            _certificateManager = certificateManager;
            _certificateConfig = certificateConfig;
        }

        public ICipherParameters Create(ConnectionEnd end, ConnectionDirection direction)
        {
            var publicKey = (ECPublicKey)_certificateConfig.Certificate.SubjectPublicKey;

            switch (end)
            {
                case ConnectionEnd.Client:
                    return new ECCipherParameters(publicKey.Parameters, publicKey);
                case ConnectionEnd.Server:
                    var privateKey = (ECPrivateKey)_certificateManager.GetPrivateKey(publicKey);
                    return new ECCipherParameters(publicKey.Parameters, privateKey);
                default:
                    throw new ArgumentOutOfRangeException(nameof(end), end, null);
            }
        }
    }
}