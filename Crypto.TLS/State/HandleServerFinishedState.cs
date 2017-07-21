using System;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Records;
using Crypto.TLS.Services;
using Crypto.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State
{
    public class HandleServerFinishedState : IState
    {
        public ConnectionState State => ConnectionState.RecievedServerFinished;

        private readonly IServiceProvider _serviceProvider;

        private readonly Connection _connection;
        private readonly HandshakeWriter _writer;
        private readonly HandshakeFinishedService _handshakeFinishedService;

        private readonly VersionConfig _versionConfig;
        private readonly CipherSuiteConfig _cipherSuiteConfig;

        private readonly FinishedMessage _handshake;

        public HandleServerFinishedState(
            IServiceProvider serviceProvider,

            Connection connection,
            HandshakeWriter writer,
            HandshakeFinishedService handshakeFinishedService,

            VersionConfig versionConfig,
            CipherSuiteConfig cipherSuiteConfig,

            FinishedMessage handshake)
        {
            _serviceProvider = serviceProvider;

            _connection = connection;
            _writer = writer;
            _handshakeFinishedService = handshakeFinishedService;


            _versionConfig = versionConfig;
            _cipherSuiteConfig = cipherSuiteConfig;

            _handshake = handshake;
        }

        public static HandleServerFinishedState New(IServiceProvider serviceProvider, FinishedMessage handshake)
        {
            return new HandleServerFinishedState(
                serviceProvider,

                serviceProvider.GetService<Connection>(),
                serviceProvider.GetService<HandshakeWriter>(),
                serviceProvider.GetService<HandshakeFinishedService>(),

                serviceProvider.GetService<VersionConfig>(),
                serviceProvider.GetService<CipherSuiteConfig>(),

                handshake
            );
        }

        public IState Run()
        {
            SecurityAssert.Assert(_handshakeFinishedService.Verify(_handshake));

            return _serviceProvider.GetRequiredService<ActiveState>();
        }
    }
}