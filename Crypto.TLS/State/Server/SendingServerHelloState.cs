﻿using System;
using System.Collections.Generic;
using System.Linq;
using Crypto.TLS.Config;
using Crypto.TLS.Extensions;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Suites.Providers;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State.Server
{
    public class SendingServerHelloState : IState
    {
        public ConnectionState State => ConnectionState.SendingServerHello;

        private readonly IServiceProvider _serviceProvider;
        private readonly ICipherSuitesProvider _cipherSuitesProvider;

        private readonly HandshakeWriter _writer;

        private readonly VersionConfig _versionConfig;
        private readonly RandomConfig _randomConfig;
        private readonly SessionConfig _sessionConfig;
        private readonly CipherSuiteConfig _cipherSuiteConfig;

        public SendingServerHelloState(
            IServiceProvider serviceProvider,
            ICipherSuitesProvider cipherSuitesProvider,
            
            HandshakeWriter writer,

            VersionConfig versionConfig,
            RandomConfig randomConfig,
            SessionConfig sessionConfig,
            CipherSuiteConfig cipherSuiteConfig)
        {
            _serviceProvider = serviceProvider;
            _cipherSuitesProvider = cipherSuitesProvider;

            _writer = writer;

            _versionConfig = versionConfig;
            _randomConfig = randomConfig;
            _sessionConfig = sessionConfig;
            _cipherSuiteConfig = cipherSuiteConfig;
        }

        public IState Run()
        {
            foreach (var message in CreateMessages())
            {
                _writer.Write(message);
            }

            return _serviceProvider.GetRequiredService<SentServerHelloState>();
        }

        private IEnumerable<HandshakeMessage> CreateMessages()
        {
            yield return CreateHello();
            foreach (var message in CreateKeyExchangeMessages())
            {
                yield return message;
            }
            yield return CreateDone();
        }

        private HandshakeMessage CreateHello()
        {
            if (_randomConfig.Server is null)
            {
                throw new InvalidOperationException("Random config is not initialized");
            }
            if (_sessionConfig.Id is null)
            {
                throw new InvalidOperationException("Session config is not initialized");
            }

            var extensionHellos = CreateHelloExtensions();

            return new ServerHelloMessage(
                _versionConfig.Version,
                _randomConfig.Server,
                _sessionConfig.Id,
                extensionHellos,
                _cipherSuiteConfig.CipherSuite,
                _cipherSuiteConfig.CompressionMethod);
        }

        private HelloExtension[] CreateHelloExtensions()
        {
            var extensions = _serviceProvider.ResolveAllExtensions();

            return extensions
                .SelectMany(x => x.GenerateHelloExtensions())
                .ToArray();
        }

        private IEnumerable<HandshakeMessage> CreateKeyExchangeMessages()
        {
            var keyExchange = _cipherSuitesProvider.ResolveKeyExchange(_cipherSuiteConfig.CipherSuite);

            return keyExchange.GenerateServerHandshakeMessages();
        }

        private HandshakeMessage CreateDone()
        {
            return new ServerHelloDoneMessage();
        }
    }
}