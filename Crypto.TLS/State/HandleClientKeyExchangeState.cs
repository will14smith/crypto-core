using System;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Suites.Providers;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State
{
    public class HandleClientKeyExchangeState : IState
    {
        public ConnectionState State => ConnectionState.RecievedClientKeyExchange;

        private readonly IServiceProvider _serviceProvider;
        private readonly ICipherSuitesProvider _cipherSuitesProvider;

        private readonly CipherSuiteConfig _cipherSuiteConfig;
        private readonly ClientKeyExchangeMessage _handshake;
        
        public HandleClientKeyExchangeState(
            IServiceProvider serviceProvider,
            ICipherSuitesProvider cipherSuitesProvider,
            
            CipherSuiteConfig cipherSuiteConfig, 
            ClientKeyExchangeMessage handshake)
        {
            _serviceProvider = serviceProvider;
            _cipherSuitesProvider = cipherSuitesProvider;

            _cipherSuiteConfig = cipherSuiteConfig;
            _handshake = handshake;
        }

        public static HandleClientKeyExchangeState New(IServiceProvider serviceProvider, ClientKeyExchangeMessage handshake)
        {
            return new HandleClientKeyExchangeState(
                serviceProvider: serviceProvider,
                cipherSuitesProvider: serviceProvider.GetRequiredService<ICipherSuitesProvider>(),

                cipherSuiteConfig: serviceProvider.GetRequiredService<CipherSuiteConfig>(),
                handshake: handshake
            );
        }
        
        public IState Run()
        {
            // TODO is it valid to receive this message?

            var keyExchange = _cipherSuitesProvider.ResolveKeyExchange(_cipherSuiteConfig.CipherSuite);

            keyExchange.HandleClientKeyExchange(_handshake);

            return _serviceProvider.GetRequiredService<WaitingForClientChangeCipherSpecState>();
        }
    }
}