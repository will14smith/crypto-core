using System;
using System.Collections.Generic;
using System.Linq;
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
    public class ECDHKeyExchange : IKeyExchange
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IRandom _random;

        private readonly MasterSecretCalculator _masterSecretCalculator;
        private readonly CertificateManager _certificateManager;
        private readonly CipherSuiteRegistry _cipherSuiteRegistry;
        private readonly NamedCurvesRegistry _namedCurvesRegistry;

        private readonly ECDHExchangeConfig _ecdhExchangeConfig;
        private readonly SupportedGroupsConfig _supportedGroupsConfig;
        private readonly CertificateConfig _certificateConfig;

        public ECDHKeyExchange(
            IServiceProvider serviceProvider,
            IRandom random,

            MasterSecretCalculator masterSecretCalculator,
            CertificateManager certificateManager,
            CipherSuiteRegistry cipherSuiteRegistry,
            NamedCurvesRegistry namedCurvesRegistry,

            ECDHExchangeConfig ecdhExchangeConfig,
            SupportedGroupsConfig supportedGroupsConfig,
            CertificateConfig certificateConfig)
        {
            _serviceProvider = serviceProvider;
            _random = random;

            _masterSecretCalculator = masterSecretCalculator;
            _certificateManager = certificateManager;
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

                if (!(certificate.SubjectPublicKey is ECPublicKey))
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

            _ecdhExchangeConfig.Parameters = parameters;
            _ecdhExchangeConfig.D = key.D;
        }

        private Option<NamedCurve> GetCurveName(PrimeDomainParameters parameters)
        {
            return _namedCurvesRegistry.FindNameByParameters(parameters, out var name) 
                ? Option.Some(name) 
                : Option.None<NamedCurve>();
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

        private ECPrivateKey GetPrivateKey()
        {
            var cert = _certificateConfig.Certificate;
            var key = _certificateManager.GetPrivateKey(cert.SubjectPublicKey);

            var ecKey = key as ECPrivateKey;
            SecurityAssert.NotNull(ecKey);

            return ecKey;
        }
    }
}
