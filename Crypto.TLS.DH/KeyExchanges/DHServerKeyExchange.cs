using System;
using System.Collections.Generic;
using System.Numerics;
using Crypto.Certificates;
using Crypto.TLS.Config;
using Crypto.TLS.DH.Keys;
using Crypto.TLS.KeyExchanges;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.DH.KeyExchanges
{
    public class DHServerKeyExchange : IServerKeyExchange
    {
        private readonly CertificateManager _certificateManager;
        private readonly MasterSecretCalculator _masterSecretCalculator;
        
        private readonly CertificateConfig _certificateConfig;

        public DHServerKeyExchange(
            CertificateManager certificateManager,
            MasterSecretCalculator masterSecretCalculator,
            
            CertificateConfig certificateConfig)
        {
            _certificateManager = certificateManager;
            _masterSecretCalculator = masterSecretCalculator;
            
            _certificateConfig = certificateConfig;
        }
        
        public IEnumerable<HandshakeMessage> GenerateServerHandshakeMessages()
        {
            if (_certificateConfig.CertificateChain is null)
            {
                throw new InvalidOperationException("Certificate chain is not initialized");
            }
            
            yield return new CertificateMessage(_certificateConfig.CertificateChain);
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            var dhMessage = DHClientKeyExchangeMessage.Read(message.Body);
            var sharedSecret = CalculateDH(dhMessage.Yc);
            var preMasterSecret = sharedSecret.ToByteArray(Endianness.BigEndian);

            var masterSecret = _masterSecretCalculator.Compute(preMasterSecret);
            _masterSecretCalculator.ComputeKeysAndUpdateConfig(masterSecret);
        }

        private BigInteger CalculateDH(BigInteger @base)
        {
            var key = GetPrivateKey();

            return DHCalculator.Calculate(@base, key.X, key.DHPublicKey.P);
        }

        private DHPrivateKey GetPrivateKey()
        {
            if (_certificateConfig.Certificate is null)
            {
                throw new InvalidOperationException("Certificate is not initialized");
            }

            var cert = _certificateConfig.Certificate;
            var key = _certificateManager.GetPrivateKey(cert.SubjectPublicKey);

            var dhKey = key as DHPrivateKey;
            SecurityAssert.NotNull(dhKey);

            return dhKey!;
        }

    }
}