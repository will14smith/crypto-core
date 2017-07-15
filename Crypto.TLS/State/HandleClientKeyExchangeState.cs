using System;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State
{
    public class HandleClientKeyExchangeState : IState
    {
        public ConnectionState State => ConnectionState.RecievedClientKeyExchange;

        private readonly IServiceProvider _serviceProvider;

        private readonly CipherSuiteConfig _cipherSuiteConfig;
        private readonly ClientKeyExchangeMessage _handshake;
        
        public HandleClientKeyExchangeState(
            IServiceProvider serviceProvider,
            
            CipherSuiteConfig cipherSuiteConfig, 
            ClientKeyExchangeMessage handshake)
        {
            _serviceProvider = serviceProvider;
            
            _cipherSuiteConfig = cipherSuiteConfig;
            _handshake = handshake;
        }

        public static HandleClientKeyExchangeState New(IServiceProvider serviceProvider, ClientKeyExchangeMessage handshake)
        {
            return new HandleClientKeyExchangeState(
                serviceProvider: serviceProvider,

                cipherSuiteConfig: serviceProvider.GetRequiredService<CipherSuiteConfig>(),
                handshake: handshake
            );
        }
        
        public IState Run()
        {
            var keyExchange = _serviceProvider.ResolveKeyExchange(_cipherSuiteConfig.CipherSuite);

            keyExchange.HandleClientKeyExchange(_handshake);

            return _serviceProvider.GetRequiredService<WaitingForClientChangeCipherSpecState>();
        }
    }
}