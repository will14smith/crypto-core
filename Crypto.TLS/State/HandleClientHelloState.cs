﻿using System;
using System.Collections.Generic;
using Crypto.Core.Randomness;
using Crypto.TLS.Config;
using Crypto.TLS.Extensions;
using Crypto.TLS.Messages.Handshakes;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State
{
    public class HandleClientHelloState : IState
    {
        public ConnectionState State => ConnectionState.RecievedClientHello;

        private readonly IServiceProvider _serviceProvider;

        private readonly INegotiatior _negotiatior;
        private readonly IRandom _random;
        
        private readonly VersionConfig _versionConfig;
        private readonly CipherSuiteConfig _cipherSuiteConfig;
        private readonly CertificateConfig _certificateConfig;
        private readonly RandomConfig _randomConfig;
        private readonly SessionConfig _sessionConfig;

        private readonly ClientHelloMessage _handshake;

        public HandleClientHelloState(
            IServiceProvider serviceProvider,

            INegotiatior negotiatior,
            IRandom random,

            VersionConfig versionConfig,
            CipherSuiteConfig cipherSuiteConfig,
            CertificateConfig certificateConfig,
            RandomConfig randomConfig,
            SessionConfig sessionConfig,

            ClientHelloMessage handshake)
        {
            _serviceProvider = serviceProvider;
            _negotiatior = negotiatior;
            _random = random;
            _versionConfig = versionConfig;
            _cipherSuiteConfig = cipherSuiteConfig;
            _certificateConfig = certificateConfig;
            _randomConfig = randomConfig;
            _sessionConfig = sessionConfig;
            _handshake = handshake;
        }

        public static HandleClientHelloState New(IServiceProvider serviceProvider, ClientHelloMessage handshake)
        {
            return new HandleClientHelloState(
                serviceProvider: serviceProvider,

                negotiatior: serviceProvider.GetRequiredService<INegotiatior>(),
                random: serviceProvider.GetRequiredService<IRandom>(),

                versionConfig: serviceProvider.GetRequiredService<VersionConfig>(),
                cipherSuiteConfig: serviceProvider.GetRequiredService<CipherSuiteConfig>(),
                certificateConfig: serviceProvider.GetRequiredService<CertificateConfig>(),
                randomConfig: serviceProvider.GetRequiredService<RandomConfig>(),
                sessionConfig: serviceProvider.GetRequiredService<SessionConfig>(),

                handshake: handshake
            );
        }

        public IState Run()
        {
            _versionConfig.Version = _negotiatior.DecideVersion(_handshake.Version);
            _cipherSuiteConfig.CipherSuite = _negotiatior.DecideCipherSuite(_handshake.CipherSuites);
            _cipherSuiteConfig.CompressionMethod = _negotiatior.DecideCompression(_handshake.CompressionMethods);
            // TODO this might need the extensions to be processed before
            _certificateConfig.CertificateChain = _negotiatior.DecideCertificateChain();

            _randomConfig.Client = _handshake.RandomBytes;
            // TODO move this to an earlier state?
            _randomConfig.Server = _random.RandomBytes(32);

            // TODO Generate a session id
            _sessionConfig.Id = new byte[0];

            HandleClientExtensions(_handshake.Extensions);

            return _serviceProvider.GetRequiredService<SendingServerHelloState>();
        }

        private void HandleClientExtensions(IEnumerable<HelloExtension> extensions)
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