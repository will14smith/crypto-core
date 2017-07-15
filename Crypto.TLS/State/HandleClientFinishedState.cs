using System;
using System.Linq;
using Crypto.TLS.Config;
using Crypto.TLS.Hashing;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Records;
using Crypto.TLS.Services;
using Crypto.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State
{
    public class HandleClientFinishedState : IState
    {
        public ConnectionState State => ConnectionState.RecievedClientFinished;

        private readonly IServiceProvider _serviceProvider;
        
        private readonly Connection _connection;
        private readonly HandshakeWriter _writer;

        private readonly EndConfig _endConfig;
        private readonly KeyConfig _keyConfig;
        private readonly HandshakeConfig _handshakeConfig;
        private readonly VersionConfig _versionConfig;
        private readonly CipherSuiteConfig _cipherSuiteConfig;

        private readonly FinishedMessage _handshake;

        public HandleClientFinishedState(
            IServiceProvider serviceProvider,

            Connection connection,
            HandshakeWriter writer,

            EndConfig endConfig,
            KeyConfig keyConfig,
            HandshakeConfig handshakeConfig,
            VersionConfig versionConfig,
            CipherSuiteConfig cipherSuiteConfig,

            FinishedMessage handshake)
        {
            _serviceProvider = serviceProvider;
            
            _connection = connection;
            _writer = writer;

            _endConfig = endConfig;
            _keyConfig = keyConfig;
            _handshakeConfig = handshakeConfig;
            _versionConfig = versionConfig;
            _cipherSuiteConfig = cipherSuiteConfig;

            _handshake = handshake;
        }

        public static HandleClientFinishedState New(IServiceProvider serviceProvider, FinishedMessage handshake)
        {
            return new HandleClientFinishedState(
                serviceProvider,

                serviceProvider.GetService<Connection>(),
                serviceProvider.GetService<HandshakeWriter>(),

                serviceProvider.GetService<EndConfig>(),
                serviceProvider.GetService<KeyConfig>(),
                serviceProvider.GetService<HandshakeConfig>(),
                serviceProvider.GetService<VersionConfig>(),
                serviceProvider.GetService<CipherSuiteConfig>(),

                handshake
            );
        }

        public IState Run()
        {
            VerifyHandshake();

            _connection.WriteRecord(new Record(RecordType.ChangeCipherSpec, _versionConfig.Version, new byte[] { 1 }));
            _connection.RecordWriterStrategy = _serviceProvider.GetRecordWriterStrategy(_cipherSuiteConfig.CipherSuite);

            _writer.Write(GenerateFinishedMessage());
                
            throw new NotImplementedException();
        }

        private void VerifyHandshake()
        {
            var prfDigest = _serviceProvider.ResolvePRFHash(_cipherSuiteConfig.CipherSuite);
            var prf = new PRF(prfDigest);

            var label = _endConfig.End == ConnectionEnd.Server ? "client finished" : "server finished";
            var expectedData =
                prf.Digest(_keyConfig.Master, label, _handshake.VerifyExpectedHash)
                    .Take(FinishedMessage.VerifyDataLength)
                    .ToArray();

            SecurityAssert.AssertHash(_handshake.VerifyActual, expectedData);
        }

        private FinishedMessage GenerateFinishedMessage()
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