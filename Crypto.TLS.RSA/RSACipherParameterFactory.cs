using System;
using Crypto.Certificates;
using Crypto.Certificates.Parameters;
using Crypto.Core.Encryption.Parameters;
using Crypto.TLS.Config;
using Crypto.TLS.Services;

namespace Crypto.TLS.RSA
{
    public class RSACipherParameterFactory : ICipherParameterFactory
    {
        private readonly CertificateManager _certificateManager;
        private readonly CertificateConfig _certificateConfig;

        public RSACipherParameterFactory(
            CertificateManager certificateManager, 
            CertificateConfig certificateConfig)
        {
            _certificateManager = certificateManager;
            _certificateConfig = certificateConfig;
        }

        public ICipherParameters Create(ConnectionEnd end, ConnectionDirection direction)
        {
            var publicKey = _certificateConfig.Certificate.SubjectPublicKey;
            
            switch (end)
            {
                case ConnectionEnd.Client:
                    return new PublicKeyParameter(publicKey);
                case ConnectionEnd.Server:
                    return new PrivateKeyParameter(_certificateManager.GetPrivateKey(publicKey));
                default:
                    throw new ArgumentOutOfRangeException(nameof(end), end, null);
            }
        }
    }
}
