using System;
using System.Linq;
using Crypto.Core.Randomness;
using Crypto.TLS.Config;
using Crypto.TLS.Extensions;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Suites;
using Crypto.TLS.Suites.Providers;
using Crypto.TLS.Suites.Registries;
using Crypto.Utils.IO;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State
{
    public class SendingClientHelloState : IState
    {
        public ConnectionState State => ConnectionState.SendingClientHello;

        private readonly IServiceProvider _serviceProvider;
        private readonly ICipherSuitesProvider _cipherSuitesProvider;
        private readonly CipherSuitesRegistry _cipherSuitesRegistry;

        private readonly IRandom _random;
        private readonly HandshakeWriter _writer;

        private readonly VersionConfig _versionConfig;
        private readonly RandomConfig _randomConfig;
        private readonly SessionConfig _sessionConfig;

        public SendingClientHelloState(
            IServiceProvider serviceProvider,
            ICipherSuitesProvider cipherSuitesProvider,
            CipherSuitesRegistry cipherSuitesRegistry,

            IRandom random,
            HandshakeWriter writer,

            VersionConfig versionConfig,
            RandomConfig randomConfig,
            SessionConfig sessionConfig)
        {
            _serviceProvider = serviceProvider;
            _cipherSuitesProvider = cipherSuitesProvider;
            _cipherSuitesRegistry = cipherSuitesRegistry;

            _random = random;
            _writer = writer;

            _versionConfig = versionConfig;
            _randomConfig = randomConfig;
            _sessionConfig = sessionConfig;
        }

        public IState Run()
        {
            _versionConfig.Version = TLSVersion.TLS1_2;
            _randomConfig.Client = GenerateClientRandom();

            var cipherSuites = _cipherSuitesProvider
                .GetAllSupportedSuites(_cipherSuitesRegistry)
                .ToArray();
            var compressionMethods = new[] { CompressionMethod.Null };

            var extensions = _serviceProvider.ResolveAllExtensions();
            var extensionHellos = extensions.SelectMany(x => x.GenerateHelloExtensions()).ToArray();

            //TODO session id is not supported
            _sessionConfig.Id = new byte[0];

            var message = new ClientHelloMessage(
                version: _versionConfig.Version,
                randomBytes: _randomConfig.Client,
                sessionId: _sessionConfig.Id,
                extensions: extensionHellos,
                cipherSuites: cipherSuites,
                compressionMethods: compressionMethods);

            _writer.Write(message);

            return _serviceProvider.GetRequiredService<WaitingForServerHelloState>();
        }

        private ReadOnlyMemory<byte> GenerateClientRandom()
        {
            var b = new byte[32];

            var epoch = (int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
            EndianBitConverter.Big.CopyBytes(epoch, b, 0);

            _random.RandomBytes(b.AsSpan(4));

            return b;
        }
    }
}