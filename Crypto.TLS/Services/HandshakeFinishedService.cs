using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Crypto.TLS.Config;
using Crypto.TLS.Hashing;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;

namespace Crypto.TLS.Services
{
    public class HandshakeFinishedService
    {
        private readonly IServiceProvider _serviceProvider;
        
        private readonly CipherSuiteConfig _cipherSuiteConfig;
        private readonly EndConfig _endConfig;
        private readonly HandshakeConfig _handshakeConfig;
        private readonly KeyConfig _keyConfig;

        public HandshakeFinishedService(
            IServiceProvider serviceProvider,
            
            CipherSuiteConfig cipherSuiteConfig,
            EndConfig endConfig,
            HandshakeConfig handshakeConfig,
            KeyConfig keyConfig)
        {
            _serviceProvider = serviceProvider;
            
            _cipherSuiteConfig = cipherSuiteConfig;
            _endConfig = endConfig;
            _handshakeConfig = handshakeConfig;
            _keyConfig = keyConfig;
        }
        
        public bool Verify(FinishedMessage message)
        {
            var prfDigest = _serviceProvider.ResolvePRFHash(_cipherSuiteConfig.CipherSuite);
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
            var prfDigest = _serviceProvider.ResolvePRFHash(_cipherSuiteConfig.CipherSuite);
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
