using System;
using System.Collections.Generic;
using Crypto.TLS.Config;
using Crypto.TLS.Extensions;
using Crypto.TLS.Messages.Handshakes;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State
{
    public class HandleServerHelloState : IState
    {
        public ConnectionState State => ConnectionState.RecievedServerHello;

        private readonly IServiceProvider _serviceProvider;
        
        private readonly VersionConfig _versionConfig;
        private readonly CipherSuiteConfig _cipherSuiteConfig;
        private readonly RandomConfig _randomConfig;
        private readonly SessionConfig _sessionConfig;

        private readonly ServerHelloMessage _handshake;

        private HandleServerHelloState(
            IServiceProvider serviceProvider,
            
            VersionConfig versionConfig,
            CipherSuiteConfig cipherSuiteConfig,
            RandomConfig randomConfig,
            SessionConfig sessionConfig,
            
            ServerHelloMessage handshake)
        {
            _serviceProvider = serviceProvider;
            _versionConfig = versionConfig;
            _cipherSuiteConfig = cipherSuiteConfig;
            _randomConfig = randomConfig;
            _sessionConfig = sessionConfig;
            _handshake = handshake;
        }

        public static HandleServerHelloState New(IServiceProvider serviceProvider, ServerHelloMessage handshake)
        {
            return new HandleServerHelloState(
                serviceProvider,
                
                serviceProvider.GetRequiredService<VersionConfig>(),
                serviceProvider.GetRequiredService<CipherSuiteConfig>(),
                serviceProvider.GetRequiredService<RandomConfig>(),
                serviceProvider.GetRequiredService<SessionConfig>(),

                handshake);
        }

        public IState Run()
        {
            _versionConfig.Version = _handshake.Version;
            _cipherSuiteConfig.CipherSuite = _handshake.CipherSuite;
            _cipherSuiteConfig.CompressionMethod = _handshake.CompressionMethod;

            _randomConfig.Server = _handshake.RandomBytes;

            _sessionConfig.Id = _handshake.SessionId;

            HandleServerExtensions(_handshake.Extensions);

            return _serviceProvider.GetRequiredService<WaitingForServerHelloFollowupState>();
        }

        private void HandleServerExtensions(IEnumerable<HelloExtension> extensions)
        {
            foreach (var extensionMessage in extensions)
            {
                var extension = _serviceProvider.TryResolveExtension(extensionMessage.Type);
                if (extension.HasValue)
                {
                    extension.Value.HandleHello(extensionMessage);
                }
            }
        }
    }
}