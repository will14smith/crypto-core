using System;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Records;
using Crypto.TLS.Services;
using Crypto.TLS.Suites;
using Crypto.TLS.Suites.Providers;
using Crypto.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State.Server
{
    public class HandleClientFinishedState : IState
    {
        public ConnectionState State => ConnectionState.RecievedClientFinished;

        private readonly IServiceProvider _serviceProvider;
        private readonly ICipherSuitesProvider _cipherSuitesProvider;

        private readonly Connection _connection;
        private readonly HandshakeWriter _writer;
        private readonly HandshakeFinishedService _handshakeFinishedService;

        private readonly VersionConfig _versionConfig;
        private readonly CipherSuiteConfig _cipherSuiteConfig;

        private readonly FinishedMessage _handshake;

        public HandleClientFinishedState(
            IServiceProvider serviceProvider,
            ICipherSuitesProvider cipherSuitesProvider,
            
            Connection connection,
            HandshakeWriter writer,
            HandshakeFinishedService handshakeFinishedService,

            VersionConfig versionConfig,
            CipherSuiteConfig cipherSuiteConfig,

            FinishedMessage handshake)
        {
            _serviceProvider = serviceProvider;
            _cipherSuitesProvider = cipherSuitesProvider;

            _connection = connection;
            _writer = writer;
            _handshakeFinishedService = handshakeFinishedService;


            _versionConfig = versionConfig;
            _cipherSuiteConfig = cipherSuiteConfig;

            _handshake = handshake;
        }

        public static HandleClientFinishedState New(IServiceProvider serviceProvider, FinishedMessage handshake)
        {
            return new HandleClientFinishedState(
                serviceProvider,
                serviceProvider.GetRequiredService<ICipherSuitesProvider>(),

                serviceProvider.GetRequiredService<Connection>(),
                serviceProvider.GetRequiredService<HandshakeWriter>(),
                serviceProvider.GetRequiredService<HandshakeFinishedService>(),

                serviceProvider.GetRequiredService<VersionConfig>(),
                serviceProvider.GetRequiredService<CipherSuiteConfig>(),

                handshake
            );
        }

        public IState Run()
        {
            SecurityAssert.Assert(_handshakeFinishedService.Verify(_handshake));

            _connection.WriteRecord(new Record(RecordType.ChangeCipherSpec, _versionConfig.Version, new byte[] { 1 }));
            _connection.RecordWriterStrategy = _cipherSuitesProvider.GetRecordWriterStrategy(_serviceProvider, _cipherSuiteConfig.CipherSuite);

            _writer.Write(_handshakeFinishedService.Generate());

            return _serviceProvider.GetRequiredService<ActiveState>();
        }
    }
}