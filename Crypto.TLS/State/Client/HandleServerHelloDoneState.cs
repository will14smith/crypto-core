using System;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Records;
using Crypto.TLS.Services;
using Crypto.TLS.Suites;
using Crypto.TLS.Suites.Providers;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State.Client
{
    public class HandleServerHelloDoneState : IState
    {
        public ConnectionState State => ConnectionState.RecievedServerHelloDone;

        private readonly IServiceProvider _serviceProvider;
        private readonly ICipherSuitesProvider _cipherSuitesProvider;

        private readonly Connection _connection;
        private readonly HandshakeWriter _writer;
        private readonly HandshakeFinishedService _handshakeFinishedService;

        private readonly CipherSuiteConfig _cipherSuiteConfig;
        private readonly VersionConfig _versionConfig;

        public HandleServerHelloDoneState(
            IServiceProvider serviceProvider,
            ICipherSuitesProvider cipherSuitesProvider,

            Connection connection,
            HandshakeWriter writer,
            HandshakeFinishedService handshakeFinishedService,

            CipherSuiteConfig cipherSuiteConfig,
            VersionConfig versionConfig)
        {
            _serviceProvider = serviceProvider;
            _cipherSuitesProvider = cipherSuitesProvider;

            _connection = connection;
            _writer = writer;
            _handshakeFinishedService = handshakeFinishedService;

            _cipherSuiteConfig = cipherSuiteConfig;
            _versionConfig = versionConfig;
        }

        public static HandleServerHelloDoneState New(IServiceProvider serviceProvider, ServerHelloDoneMessage handshake)
        {
            return new HandleServerHelloDoneState(
                serviceProvider,
                serviceProvider.GetRequiredService<ICipherSuitesProvider>(),

                serviceProvider.GetRequiredService<Connection>(),
                serviceProvider.GetRequiredService<HandshakeWriter>(),
                serviceProvider.GetRequiredService<HandshakeFinishedService>(),

                serviceProvider.GetRequiredService<CipherSuiteConfig>(),
                serviceProvider.GetRequiredService<VersionConfig>());
        }

        public IState Run()
        {
            // TODO send cert (if requested)

            SendKeyExchange();

            // TODO send cert verified (if request & required)

            SendChangeCipherSpec();
            SendFinished();

            return _serviceProvider.GetRequiredService<WaitingForServerChangeCipherSpecState>();
        }

        private void SendKeyExchange()
        {
            var keyExchange = _cipherSuitesProvider.ResolveKeyExchange(_cipherSuiteConfig.CipherSuite);

            var messages = keyExchange.GenerateClientHandshakeMessages();
            foreach (var message in messages)
            {
                _writer.Write(message);
            }
        }

        private void SendChangeCipherSpec()
        {
            _connection.WriteRecord(new Record(RecordType.ChangeCipherSpec, _versionConfig.Version, new byte[] { 1 }));
            _connection.RecordWriterStrategy = _cipherSuitesProvider.GetRecordWriterStrategy(_serviceProvider, _cipherSuiteConfig.CipherSuite);
        }

        private void SendFinished()
        {
            _writer.Write(_handshakeFinishedService.Generate());
        }
    }
}