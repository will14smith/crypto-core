using System;
using System.Collections.Generic;
using Crypto.Core.Randomness;
using Crypto.TLS.Config;
using Crypto.TLS.DH.Config;
using Crypto.TLS.KeyExchanges;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.DH.KeyExchanges
{
    public class DHEServerKeyExchange : IServerKeyExchange
    {
        private readonly IServiceProvider _serviceProvider;

        private readonly IRandom _random;
        private readonly MasterSecretCalculator _masterSecretCalculator;

        private readonly DHParameterConfig _dhParameterConfig;
        private readonly DHExchangeConfig _dhExchangeConfig;
        private readonly CertificateConfig _certificateConfig;

        public DHEServerKeyExchange(
            IServiceProvider serviceProvider,

            IRandom random,
            MasterSecretCalculator masterSecretCalculator,

            DHParameterConfig dhParameterConfig,
            DHExchangeConfig dhExchangeConfig,
            CertificateConfig certificateConfig)
        {
            _serviceProvider = serviceProvider;

            _random = random;
            _masterSecretCalculator = masterSecretCalculator;

            _dhParameterConfig = dhParameterConfig;
            _dhExchangeConfig = dhExchangeConfig;
            _certificateConfig = certificateConfig;
        }


        public IEnumerable<HandshakeMessage> GenerateServerHandshakeMessages()
        {
            if (_certificateConfig.CertificateChain is null)
            {
                throw new InvalidOperationException("Certificate chain is not initialized");
            }

            // 512 is "approx" 256-bits of security
            _dhExchangeConfig.X = _random.RandomBig(512);

            var ys = DHCalculator.Calculate(_dhParameterConfig.G, _dhExchangeConfig.X, _dhParameterConfig.P);

            yield return new CertificateMessage(_certificateConfig.CertificateChain);
            yield return new DHServerKeyExchangeMessage(_serviceProvider, _dhParameterConfig.P, _dhParameterConfig.G, ys);
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            var dhMessage = DHClientKeyExchangeMessage.Read(message.Body);
            var sharedSecret = DHCalculator.Calculate(dhMessage.Yc, _dhExchangeConfig.X, _dhParameterConfig.P);
            var preMasterSecret = sharedSecret.ToByteArray(Endianness.BigEndian);

            var masterSecret = _masterSecretCalculator.Compute(preMasterSecret);
            _masterSecretCalculator.ComputeKeysAndUpdateConfig(masterSecret);
        }
    }
}