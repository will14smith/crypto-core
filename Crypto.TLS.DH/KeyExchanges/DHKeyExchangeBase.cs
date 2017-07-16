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
    public abstract class DHKeyExchangeBase : IKeyExchange
    {
        protected MasterSecretCalculator MasterSecretCalculator { get; }
        protected CertificateConfig CertificateConfig { get; }

        protected DHKeyExchangeBase(
            MasterSecretCalculator masterSecretCalculator,
            CertificateConfig certificateConfig)
        {
            MasterSecretCalculator = masterSecretCalculator;
            CertificateConfig = certificateConfig;
        }

        public virtual bool IsCompatible(CipherSuite cipherSuite, X509Certificate certificate)
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

        public virtual IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            yield return new CertificateMessage(CertificateConfig.CertificateChain);
        }

        public virtual void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            var yc = ReadMessage(message);
            var sharedSecret = CalculatedSharedSecret(yc);
            var preMasterSecret = sharedSecret.ToByteArray(Endianness.BigEndian);

            var masterSecret = MasterSecretCalculator.Compute(preMasterSecret);
            MasterSecretCalculator.ComputeKeysAndUpdateConfig(masterSecret);
        }
        
        public abstract BigInteger CalculatedSharedSecret(BigInteger yc);

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