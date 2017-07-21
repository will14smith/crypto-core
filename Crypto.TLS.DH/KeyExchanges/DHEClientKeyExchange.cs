using System;
using System.Collections.Generic;
using Crypto.Core.Randomness;
using Crypto.TLS.DH.Config;
using Crypto.TLS.KeyExchanges;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.DH.KeyExchanges
{
    public class DHEClientKeyExchange : IClientKeyExchange
    {
        private readonly IServiceProvider _serviceProvider;
        
        private readonly IRandom _random;
        private readonly MasterSecretCalculator _masterSecretCalculator;

        private readonly DHParameterConfig _dhParameterConfig;
        private readonly DHExchangeConfig _dhExchangeConfig;

        public DHEClientKeyExchange(
            IServiceProvider serviceProvider,
            
            IRandom random,
            MasterSecretCalculator masterSecretCalculator,
            
            DHParameterConfig dhParameterConfig,
            DHExchangeConfig dhExchangeConfig)
        {
            _serviceProvider = serviceProvider;
            
            _random = random;
            _masterSecretCalculator = masterSecretCalculator;

            _dhParameterConfig = dhParameterConfig;
            _dhExchangeConfig = dhExchangeConfig;
        }
        
        public void HandleServerKeyExchange(ServerKeyExchangeMessage message)
        {
            var dhMessage = DHServerKeyExchangeMessage.Read(_serviceProvider, message.Data);

            _dhParameterConfig.G = dhMessage.G;
            _dhParameterConfig.P = dhMessage.P;

            // 512 is "approx" 256-bits of security
            _dhExchangeConfig.X = _random.RandomBig(512);

            var sharedSecret = DHCalculator.Calculate(dhMessage.Ys, _dhExchangeConfig.X, _dhParameterConfig.P);
            var preMasterSecret = sharedSecret.ToByteArray(Endianness.BigEndian);

            var masterSecret = _masterSecretCalculator.Compute(preMasterSecret);
            _masterSecretCalculator.ComputeKeysAndUpdateConfig(masterSecret);
        }

        public IEnumerable<HandshakeMessage> GenerateClientHandshakeMessages()
        {
            var yc = DHCalculator.Calculate(_dhParameterConfig.G, _dhExchangeConfig.X, _dhParameterConfig.P);

            yield return new DHClientKeyExchangeMessage(yc);
        }
    }
}