using System.Linq;
using Crypto.TLS.Config;
using Crypto.TLS.Hashing;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Suites.Providers;

namespace Crypto.TLS.Services
{
    public class HandshakeFinishedService
    {
        private readonly ICipherSuitesProvider _cipherSuitesProvider;
        
        private readonly CipherSuiteConfig _cipherSuiteConfig;
        private readonly EndConfig _endConfig;
        private readonly HandshakeConfig _handshakeConfig;
        private readonly KeyConfig _keyConfig;

        public HandshakeFinishedService(
            ICipherSuitesProvider cipherSuitesProvider,
            
            CipherSuiteConfig cipherSuiteConfig,
            EndConfig endConfig,
            HandshakeConfig handshakeConfig,
            KeyConfig keyConfig)
        {
            _cipherSuitesProvider = cipherSuitesProvider;
            _cipherSuiteConfig = cipherSuiteConfig;
            _endConfig = endConfig;
            _handshakeConfig = handshakeConfig;
            _keyConfig = keyConfig;
        }
        
        public bool Verify(FinishedMessage message)
        {
            var prfDigest = _cipherSuitesProvider.ResolvePRFHash(_cipherSuiteConfig.CipherSuite);
            var prf = new PRF(prfDigest);

            var label = _endConfig.End == ConnectionEnd.Server ? "client finished" : "server finished";
            var expectedData =
                prf.Digest(_keyConfig.Master, label, message.VerifyExpectedHash)
                    .Take(FinishedMessage.VerifyDataLength)
                    .ToArray();

            return expectedData.SequenceEqual(message.VerifyActual);
        }

        public FinishedMessage Generate()
        {
            var prfDigest = _cipherSuitesProvider.ResolvePRFHash(_cipherSuiteConfig.CipherSuite);
            var prf = new PRF(prfDigest);

            var label = _endConfig.End == ConnectionEnd.Server ? "server finished" : "client finished";
            var handshakeVerifyHash = _handshakeConfig.ComputeVerification(prfDigest);

            var verifyData =
                prf.Digest(_keyConfig.Master, label, handshakeVerifyHash)
                    .Take(FinishedMessage.VerifyDataLength)
                    .ToArray();

            return new FinishedMessage(verifyData, handshakeVerifyHash);
        }

    }
}
