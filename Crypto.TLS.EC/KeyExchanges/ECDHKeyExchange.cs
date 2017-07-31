using System;
using System.Collections.Generic;
using System.Linq;
using Crypto.Certificates;
using Crypto.EC.Maths;
using Crypto.EC.Parameters;
using Crypto.TLS.Config;
using Crypto.TLS.EC.Config;
using Crypto.TLS.EC.Services;
using Crypto.TLS.KeyExchanges;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Suites.Registries;
using Crypto.Utils;

namespace Crypto.TLS.EC.KeyExchanges
{
    public class ECDHKeyExchange : ECDHKeyExchangeBase
    {
        private readonly CertificateManager _certificateManager;
        private readonly NamedCurvesRegistry _namedCurvesRegistry;

        private readonly SupportedGroupsConfig _supportedGroupsConfig;

        public ECDHKeyExchange(
            MasterSecretCalculator masterSecretCalculator,
            CertificateManager certificateManager,
            CipherSuitesRegistry cipherSuitesRegistry,
            NamedCurvesRegistry namedCurvesRegistry,

            ECDHExchangeConfig ecdhExchangeConfig,
            SupportedGroupsConfig supportedGroupsConfig,
            CertificateConfig certificateConfig)
                : base(
                    masterSecretCalculator,
                    cipherSuitesRegistry,

                    ecdhExchangeConfig,
                    certificateConfig)
        {
            _certificateManager = certificateManager;
            _namedCurvesRegistry = namedCurvesRegistry;

            _supportedGroupsConfig = supportedGroupsConfig;
        }

        public override IEnumerable<HandshakeMessage> GenerateServerHandshakeMessages()
        {
            NegotiateParameters();

            foreach (var message in base.GenerateServerHandshakeMessages())
            {
                yield return message;
            }
        }

        private void NegotiateParameters()
        {
            var key = GetPrivateKey();
            var parameters = key.ECPublicKey.Parameters;

            var name = GetCurveName(parameters);
            if (name.HasValue)
            {
                SecurityAssert.Assert(_supportedGroupsConfig.SupportedGroups.Contains(name.Value));
            }
            else
            {
                throw new NotImplementedException("EXPLICIT");
            }

            ECDHExchangeConfig.Parameters = parameters;
            ECDHExchangeConfig.D = key.D;
        }

        private Option<NamedCurve> GetCurveName(DomainParameters parameters)
        {
            return _namedCurvesRegistry.FindNameByParameters(parameters, out var name)
                ? Option.Some(name)
                : Option.None<NamedCurve>();
        }

        private ECPrivateKey GetPrivateKey()
        {
            var cert = CertificateConfig.Certificate;
            var key = _certificateManager.GetPrivateKey(cert.SubjectPublicKey);

            var ecKey = key as ECPrivateKey;
            SecurityAssert.NotNull(ecKey);

            return ecKey;
        }
    }
}
