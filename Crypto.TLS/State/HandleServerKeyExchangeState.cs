using System;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State
{
    public class HandleServerKeyExchangeState : IState
    {
        public ConnectionState State => ConnectionState.RecievedServerKeyExchange;

        private readonly IServiceProvider _serviceProvider;
        
        private readonly CipherSuiteConfig _cipherSuiteConfig;

        private readonly ServerKeyExchangeMessage _handshake;

        private HandleServerKeyExchangeState(
            IServiceProvider serviceProvider,
            
            CipherSuiteConfig cipherSuiteConfig,
            
            ServerKeyExchangeMessage handshake)
        {
            _serviceProvider = serviceProvider;
            
            _cipherSuiteConfig = cipherSuiteConfig;
            
            _handshake = handshake;
        }

        public static HandleServerKeyExchangeState New(IServiceProvider serviceProvider, ServerKeyExchangeMessage handshake)
        {
            return new HandleServerKeyExchangeState(
                serviceProvider,
                
                serviceProvider.GetRequiredService<CipherSuiteConfig>(),
                
                handshake);
        }

        public IState Run()
        {
            // TODO is it valid to receive this message?

            var keyExchange = _serviceProvider.ResolveKeyExchange(_cipherSuiteConfig.CipherSuite);

            keyExchange.HandleServerKeyExchange(_handshake);

            return _serviceProvider.GetRequiredService<WaitingForServerKeyExchangeFollowupState>();
        }
    }
}