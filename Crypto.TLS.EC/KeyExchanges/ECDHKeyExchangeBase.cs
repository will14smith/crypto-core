﻿using System;
using System.Collections.Generic;
using Crypto.Certificates;
using Crypto.EC.Maths;
using Crypto.EC.Parameters;
using Crypto.RSA.Keys;
using Crypto.TLS.Config;
using Crypto.TLS.EC.Config;
using Crypto.TLS.KeyExchanges;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.RSA;
using Crypto.TLS.Services;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC.KeyExchanges
{
    public abstract class ECDHKeyExchangeBase : IKeyExchange
    {
        protected MasterSecretCalculator MasterSecretCalculator { get; }
        protected CipherSuiteRegistry CipherSuiteRegistry { get; }

        protected ECDHExchangeConfig ECDHExchangeConfig { get; }
        protected CertificateConfig CertificateConfig { get; }

        protected ECDHKeyExchangeBase(
            MasterSecretCalculator masterSecretCalculator,
            CipherSuiteRegistry cipherSuiteRegistry,

            ECDHExchangeConfig ecdhExchangeConfig,
            CertificateConfig certificateConfig)
        {
            MasterSecretCalculator = masterSecretCalculator;
            CipherSuiteRegistry = cipherSuiteRegistry;

            ECDHExchangeConfig = ecdhExchangeConfig;
            CertificateConfig = certificateConfig;
        }

        public virtual bool IsCompatible(CipherSuite cipherSuite, X509Certificate certificate)
        {
            var signatureAlgorithm = CipherSuiteRegistry.ResolveSignatureAlgorithm(cipherSuite);
            var requiresECKey = Equals(CipherSuiteRegistry.ResolveKeyExchange(cipherSuite), ECIdentifiers.ECDH);

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

                if (requiresECKey && !(certificate.SubjectPublicKey is ECPublicKey))
                {
                    return false;
                }

                if (!requiresECKey && !(certificate.SubjectPublicKey is RSAPublicKey))
                {
                    return false;
                }

                return true;
            }

            return false;

        }

        public virtual IEnumerable<HandshakeMessage> GenerateServerHandshakeMessages()
        {
            yield return new CertificateMessage(CertificateConfig.CertificateChain);
        }

        public virtual void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            var qc = ReadMessage(message);

            var sharedSecret = CalculatePoint(qc);

            var preMasterSecret = sharedSecret.X.Value.ToByteArray(Endianness.BigEndian);

            var masterSecret = MasterSecretCalculator.Compute(preMasterSecret);
            MasterSecretCalculator.ComputeKeysAndUpdateConfig(masterSecret);
        }

        public virtual IEnumerable<HandshakeMessage> GenerateClientHandshakeMessages()
        {
            throw new NotImplementedException();
        }

        public virtual void HandleServerKeyExchange(ServerKeyExchangeMessage message)
        {
            throw new NotImplementedException();
        }

        private Point ReadMessage(ClientKeyExchangeMessage message)
        {
            SecurityAssert.Assert(message.Body.Length > 0);
            var length = message.Body[0];
            SecurityAssert.Assert(message.Body.Length == length + 1);

            var param = new byte[length];
            Array.Copy(message.Body, 1, param, 0, length);

            return ECDHExchangeConfig.Parameters.Curve.PointFromBinary(param);
        }

        protected Point CalculatePoint(Point b)
        {
            return Point.Multiply(
                ECDHExchangeConfig.Parameters.Curve,
                ECDHExchangeConfig.D,
                b);
        }
    }
}
