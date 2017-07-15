using System.Collections.Generic;
using Crypto.Certificates;
using Crypto.Certificates.Parameters;
using Crypto.Core.Randomness;
using Crypto.RSA.Encryption;
using Crypto.TLS.Config;
using Crypto.TLS.KeyExchange;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;

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
            _certificateManager = certificateManager;
            _random = random;
            _masterSecretCalculator = masterSecretCalculator;
            _versionConfig = versionConfig;
            _certificateConfig = certificateConfig;
        }

        public IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            yield return new CertificateMessage(_certificateConfig.CertificateChain);
        }

        public byte[] ReadClientKeyExchange(byte[] body)
        {
            var length = EndianBitConverter.Big.ToUInt16(body, 0);
            SecurityAssert.Assert(body.Length == length + 2);

            var key = _certificateManager.GetPrivateKey(_certificateConfig.Certificate.SubjectPublicKey);
            var rsa = new RSACipher(_random);
            rsa.Init(new PrivateKeyParameter(key));

            var preMasterSecret = new byte[48];

            rsa.Decrypt(body, 2, preMasterSecret, 0, length);
            SecurityAssert.Assert(preMasterSecret[0] == _versionConfig.Version.Major);
            SecurityAssert.Assert(preMasterSecret[1] == _versionConfig.Version.Minor);

            return preMasterSecret;
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            var preMasterSecret = ReadClientKeyExchange(message.Body);

            var masterSecret = _masterSecretCalculator.Compute(preMasterSecret);
            // TODO return type?
            _masterSecretCalculator.ComputeKeysAndUpdateConfig(masterSecret);
        }
    }
}
