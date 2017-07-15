using System;
using System.Collections.Generic;
using System.Numerics;
using Crypto.Certificates;
using Crypto.Core.Randomness;
using Crypto.RSA.Keys;
using Crypto.TLS.Config;
using Crypto.TLS.DH.Config;
using Crypto.TLS.DH.Keys;
using Crypto.TLS.KeyExchange;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.DH.KeyExchanges
{
    public class DHEKeyExchange : IKeyExchange
    {
        private readonly IServiceProvider _serviceProvider;
        
        private readonly IRandom _random;
        private readonly MasterSecretCalculator _masterSecretCalculator;

        private readonly DHParameterConfig _dhParameterConfig;
        private readonly DHExchangeConfig _dhExchangeConfig;
        private readonly CertificateConfig _certificateConfig;

        public DHEKeyExchange(
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

        public bool IsCompatible(CipherSuite cipherSuite, X509Certificate certificate)
        {
            // TODO check cipherSuite == RSA/DSS
            // cert signed with RSA
            if (!RSAKeyReader.IsRSAIdentifier(certificate.SignatureAlgorithm.Algorithm))
            {
                return false;
            }

            // cert has RSA public key
            if (!(certificate.SubjectPublicKey is RSAPublicKey))
            {
                return false;
            }

            // TODO ?
            return true;
        }

        public IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            // TODO should check CipherSuite & Certificate type (RSA, DSS) match

            // 512 is "approx" 256-bits of security
            _dhExchangeConfig.X = _random.RandomBig(256);

            var serverY = BigInteger.ModPow(_dhParameterConfig.G, _dhExchangeConfig.X, _dhParameterConfig.P);

            yield return new CertificateMessage(_certificateConfig.CertificateChain);
            yield return new ServerKeyExchangeMessage(_serviceProvider, _dhParameterConfig.P, _dhParameterConfig.G, serverY);
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            var yc = ReadMessage(message);

            var sharedSecret = BigInteger.ModPow(yc, _dhExchangeConfig.X, _dhParameterConfig.P);
            var preMasterSecret = sharedSecret.ToByteArray(Endianness.BigEndian);

            var masterSecret = _masterSecretCalculator.Compute(preMasterSecret);
            _masterSecretCalculator.ComputeKeysAndUpdateConfig(masterSecret);
        }

        private static BigInteger ReadMessage(ClientKeyExchangeMessage message)
        {
            var length = EndianBitConverter.Big.ToUInt16(message.Body, 0);
            SecurityAssert.Assert(message.Body.Length == length + 2);

            var param = new byte[length];
            Array.Copy(message.Body, 2, param, 0, length);

            return param.ToBigInteger(Endianness.BigEndian);
        }
    }
}
