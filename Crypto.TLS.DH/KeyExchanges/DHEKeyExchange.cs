using System;
using System.Collections.Generic;
using System.Numerics;
using Crypto.Core.Randomness;
using Crypto.TLS.Config;
using Crypto.TLS.DH.Config;
using Crypto.TLS.KeyExchange;
using Crypto.TLS.Messages.Handshakes;

namespace Crypto.TLS.DH.KeyExchanges
{
    public class DHEKeyExchange : DHKeyExchangeBase
    {
        private readonly IServiceProvider _serviceProvider;
        
        private readonly IRandom _random;

        private readonly DHParameterConfig _dhParameterConfig;
        private readonly DHExchangeConfig _dhExchangeConfig;

        public DHEKeyExchange(
            IServiceProvider serviceProvider,

            IRandom random,
            MasterSecretCalculator masterSecretCalculator,

            DHParameterConfig dhParameterConfig,
            DHExchangeConfig dhExchangeConfig,
            CertificateConfig certificateConfig)
                :base(masterSecretCalculator, certificateConfig)
        {
            _serviceProvider = serviceProvider;
            
            _random = random;

            _dhParameterConfig = dhParameterConfig;
            _dhExchangeConfig = dhExchangeConfig;
        }
        
        public override IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            foreach (var message in base.GenerateHandshakeMessages())
            {
                yield return message;
            }
            
            // 512 is "approx" 256-bits of security
            _dhExchangeConfig.X = _random.RandomBig(256);

            var ys = BigInteger.ModPow(_dhParameterConfig.G, _dhExchangeConfig.X, _dhParameterConfig.P);

            yield return new ServerKeyExchangeMessage(_serviceProvider, _dhParameterConfig.P, _dhParameterConfig.G, ys);
        }

        public override BigInteger CalculatedSharedSecret(BigInteger yc)
        {
            return BigInteger.ModPow(yc, _dhExchangeConfig.X, _dhParameterConfig.P);
        }
    }
}
