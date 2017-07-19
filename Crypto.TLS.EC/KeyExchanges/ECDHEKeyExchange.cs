using System;
using System.Collections.Generic;
using Crypto.Core.Randomness;
using Crypto.TLS.Config;
using Crypto.TLS.EC.Config;
using Crypto.TLS.EC.Services;
using Crypto.TLS.KeyExchange;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Services;
using Crypto.Utils;

namespace Crypto.TLS.EC.KeyExchanges
{
    public class ECDHEKeyExchange : ECDHKeyExchangeBase
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IRandom _random;

        private readonly NamedCurvesRegistry _namedCurvesRegistry;

        private readonly SupportedGroupsConfig _supportedGroupsConfig;

        public ECDHEKeyExchange(
            IServiceProvider serviceProvider,
            IRandom random,

            MasterSecretCalculator masterSecretCalculator,
            CipherSuiteRegistry cipherSuiteRegistry,
            NamedCurvesRegistry namedCurvesRegistry,

            ECDHExchangeConfig ecdhExchangeConfig,
            SupportedGroupsConfig supportedGroupsConfig,
            CertificateConfig certificateConfig)
                : base(
                    masterSecretCalculator,
                    cipherSuiteRegistry,
                    
                    ecdhExchangeConfig,
                    certificateConfig)
        {
            _serviceProvider = serviceProvider;
            _random = random;

            _namedCurvesRegistry = namedCurvesRegistry;

            _supportedGroupsConfig = supportedGroupsConfig;
        }
        
        public override IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            var ecParameters = NegotiateParameters();

            foreach (var message in base.GenerateHandshakeMessages())
            {
                yield return message;
            }

            var qs = CalculatePoint(ECDHExchangeConfig.Parameters.Generator);
            var serverParams = new ServerECDHParams(ecParameters, qs);
            
            yield return new ServerKeyExchangeMessage(_serviceProvider, serverParams);
        }

        private ECParameters NegotiateParameters()
        {
            var namedCurve = GetFirstSupportedCurve();
            SecurityAssert.Assert(namedCurve.HasValue);

            ECDHExchangeConfig.Parameters = _namedCurvesRegistry.Resolve(namedCurve.Value);

            // must be in range [1, n-1] hence the -2 and +1
            var d = _random.RandomBig(ECDHExchangeConfig.Parameters.Order - 2) + 1;
            ECDHExchangeConfig.D = ECDHExchangeConfig.Parameters.Field.Value(d);

            return new ECParameters.Named(namedCurve.Value);
        }

        private Option<NamedCurve> GetFirstSupportedCurve()
        {
            foreach (var group in _supportedGroupsConfig.SupportedGroups)
            {
                if (_namedCurvesRegistry.IsSupported(group))
                {
                    return Option.Some(group);
                }
            }

            return Option.None<NamedCurve>();
        }
    }
}
