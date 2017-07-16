using System;
using System.Collections.Generic;
using Crypto.Certificates;
using Crypto.Core.Randomness;
using Crypto.EC.Maths;
using Crypto.EC.Maths.Prime;
using Crypto.EC.Parameters;
using Crypto.RSA.Keys;
using Crypto.TLS.Config;
using Crypto.TLS.EC.Config;
using Crypto.TLS.EC.Services;
using Crypto.TLS.KeyExchange;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.RSA;
using Crypto.TLS.Services;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC.KeyExchanges
{
    public class ECDHEKeyExchange : IKeyExchange
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IRandom _random;

        private readonly MasterSecretCalculator _masterSecretCalculator;
        private readonly CipherSuiteRegistry _cipherSuiteRegistry;
        private readonly NamedCurvesRegistry _namedCurvesRegistry;

        private readonly ECDHExchangeConfig _ecdhExchangeConfig;
        private readonly SupportedGroupsConfig _supportedGroupsConfig;
        private readonly CertificateConfig _certificateConfig;

        public ECDHEKeyExchange(
            IServiceProvider serviceProvider,
            IRandom random,

            MasterSecretCalculator masterSecretCalculator,
            CipherSuiteRegistry cipherSuiteRegistry,
            NamedCurvesRegistry namedCurvesRegistry,

            ECDHExchangeConfig ecdhExchangeConfig,
            SupportedGroupsConfig supportedGroupsConfig,
            CertificateConfig certificateConfig)
        {
            _serviceProvider = serviceProvider;
            _random = random;

            _masterSecretCalculator = masterSecretCalculator;
            _cipherSuiteRegistry = cipherSuiteRegistry;
            _namedCurvesRegistry = namedCurvesRegistry;

            _ecdhExchangeConfig = ecdhExchangeConfig;
            _supportedGroupsConfig = supportedGroupsConfig;
            _certificateConfig = certificateConfig;
        }

        public bool IsCompatible(CipherSuite cipherSuite, X509Certificate certificate)
        {
            var signatureAlgorithm = _cipherSuiteRegistry.ResolveSignatureAlgorithm(cipherSuite);

            if (signatureAlgorithm.Equals(ECIdentifiers.ECDSA))
            {
                if (certificate.SignatureAlgorithm.Algorithm != ECIdentifiers.ECDSAWithSHA256)
                {
                    return false;
                }

                if (!(certificate.SubjectPublicKey is ECPublicKey))
                {
                    return false;
                }

                return true;

            }

            if (signatureAlgorithm.Equals(RSAIdentifiers.RSASig))
            {
                if (!RSAKeyReader.IsRSAIdentifier(certificate.SignatureAlgorithm.Algorithm))
                {
                    return false;
                }

                if (!(certificate.SubjectPublicKey is RSAPublicKey))
                {
                    return false;
                }

                return true;
            }

            return false;
        }

        public IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            yield return new CertificateMessage(_certificateConfig.CertificateChain);

            NegotiateParameters();

            var Qs = Point<PrimeValue>.Multiply(
                _ecdhExchangeConfig.Parameters.Curve,
                _ecdhExchangeConfig.D,
                _ecdhExchangeConfig.Parameters.Generator);

            var serverParams = new ServerECDHParams(_ecdhExchangeConfig.ServerParameters, Qs);

            yield return new ServerKeyExchangeMessage(_serviceProvider, serverParams);
        }

        private void NegotiateParameters()
        {
            var namedCurve = GetFirstSupportedCurve();
            SecurityAssert.Assert(namedCurve.HasValue);

            _ecdhExchangeConfig.ServerParameters = new ECParameters.Named(namedCurve.Value);
            _ecdhExchangeConfig.Parameters = _namedCurvesRegistry.Resolve(namedCurve.Value);

            // must be in range [1, n-1] hence the -2 and +1
            var d = _random.RandomBig(_ecdhExchangeConfig.Parameters.Order - 2) + 1;
            _ecdhExchangeConfig.D = _ecdhExchangeConfig.Parameters.Field.Int(d);
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

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            var qc = ReadMessage(message);

            var sharedSecret = Point<PrimeValue>.Multiply(
                _ecdhExchangeConfig.Parameters.Curve,
                _ecdhExchangeConfig.D,
                qc);

            var preMasterSecret = sharedSecret.X.ToInt().ToByteArray(Endianness.BigEndian);

            var masterSecret = _masterSecretCalculator.Compute(preMasterSecret);
            _masterSecretCalculator.ComputeKeysAndUpdateConfig(masterSecret);
        }

        // TODO make more generic
        private Point<PrimeValue> ReadMessage(ClientKeyExchangeMessage message)
        {
            SecurityAssert.Assert(message.Body.Length > 0);
            var length = message.Body[0];
            SecurityAssert.Assert(message.Body.Length == length + 1);

            var param = new byte[length];
            Array.Copy(message.Body, 1, param, 0, length);

            return _ecdhExchangeConfig.Parameters.Curve.PointFromBinary(param);
        }
    }
}
