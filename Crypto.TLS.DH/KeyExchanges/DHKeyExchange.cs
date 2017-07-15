using System;
using System.Collections.Generic;
using System.Numerics;
using Crypto.Certificates;
using Crypto.RSA.Keys;
using Crypto.TLS.Config;
using Crypto.TLS.DH.Keys;
using Crypto.TLS.KeyExchange;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.DH.KeyExchanges
{
    public class DHKeyExchange : IKeyExchange
    {
        private readonly CertificateManager _certificateManager;
        private readonly MasterSecretCalculator _masterSecretCalculator;

        private readonly CertificateConfig _certificateConfig;

        public DHKeyExchange(
            CertificateManager certificateManager,
            MasterSecretCalculator masterSecretCalculator,

            CertificateConfig certificateConfig)
        {
            _certificateManager = certificateManager;
            _masterSecretCalculator = masterSecretCalculator;

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

            // cert has DH public key
            if (!(certificate.SubjectPublicKey is DHPublicKey))
            {
                return false;
            }

            // TODO ?
            return true;
        }

        public IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            yield return new CertificateMessage(_certificateConfig.CertificateChain);
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            var key = GetPrivateKey();

            var yc = ReadMessage(message);

            var sharedSecret = BigInteger.ModPow(yc, key.X, key.DHPublicKey.P);
            var preMasterSecret = sharedSecret.ToByteArray(Endianness.BigEndian);

            var masterSecret = _masterSecretCalculator.Compute(preMasterSecret);
            _masterSecretCalculator.ComputeKeysAndUpdateConfig(masterSecret);
        }

        private DHPrivateKey GetPrivateKey()
        {
            var cert = _certificateConfig.Certificate;
            var key = _certificateManager.GetPrivateKey(cert.SubjectPublicKey);

            var dhKey = key as DHPrivateKey;
            SecurityAssert.NotNull(dhKey);

            return dhKey;
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
