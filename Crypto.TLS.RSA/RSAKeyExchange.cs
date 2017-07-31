using System.Collections.Generic;
using Crypto.Certificates;
using Crypto.Core.Randomness;
using Crypto.RSA.Encryption;
using Crypto.RSA.Keys;
using Crypto.TLS.Config;
using Crypto.TLS.KeyExchanges;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.RSA
{
    public class RSAKeyExchange : IKeyExchange
    {
        private readonly IRandom _random;
        private readonly CertificateManager _certificateManager;
        private readonly MasterSecretCalculator _masterSecretCalculator;

        private readonly VersionConfig _versionConfig;
        private readonly CertificateConfig _certificateConfig;

        public RSAKeyExchange(
            IRandom random,
            CertificateManager certificateManager,
            MasterSecretCalculator masterSecretCalculator,

            VersionConfig versionConfig,
            CertificateConfig certificateConfig)
        {
            _random = random;
            _certificateManager = certificateManager;
            _masterSecretCalculator = masterSecretCalculator;
            
            _versionConfig = versionConfig;
            _certificateConfig = certificateConfig;
        }

        public bool IsCompatible(CipherSuite cipherSuite, X509Certificate certificate)
        {
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

        public IEnumerable<HandshakeMessage> GenerateServerHandshakeMessages()
        {
            yield return new CertificateMessage(_certificateConfig.CertificateChain);
        }
        
        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            var preMasterSecret = ReadMessage(message.Body);

            var masterSecret = _masterSecretCalculator.Compute(preMasterSecret);
            // TODO return type?
            _masterSecretCalculator.ComputeKeysAndUpdateConfig(masterSecret);
        }

        public IEnumerable<HandshakeMessage> GenerateClientHandshakeMessages()
        {
            throw new System.NotImplementedException();
        }

        public void HandleServerKeyExchange(ServerKeyExchangeMessage message)
        {
            throw new System.NotImplementedException();
        }

        private byte[] ReadMessage(byte[] body)
        {
            var length = EndianBitConverter.Big.ToUInt16(body, 0);
            SecurityAssert.Assert(body.Length == length + 2);

            var key = (RSAPrivateKey)_certificateManager.GetPrivateKey(_certificateConfig.Certificate.SubjectPublicKey);
            var rsa = new RSACipher(_random);
            rsa.Init(new RSAPrivateKeyParameter(key));

            var preMasterSecret = new byte[48];

            rsa.Decrypt(body, 2, preMasterSecret, 0, length);
            SecurityAssert.Assert(preMasterSecret[0] == _versionConfig.Version.Major);
            SecurityAssert.Assert(preMasterSecret[1] == _versionConfig.Version.Minor);

            return preMasterSecret;
        }
    }
}
