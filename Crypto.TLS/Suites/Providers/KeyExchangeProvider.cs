using System;
using Crypto.TLS.Identifiers;
using Crypto.TLS.KeyExchanges;
using Crypto.TLS.Suites.Registries;

namespace Crypto.TLS.Suites.Providers
{
    internal class KeyExchangeProvider : IKeyExchangeProvider
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly KeyExchangeRegistry _keyExchangeRegistry;

        public KeyExchangeProvider(
            IServiceProvider serviceProvider,
            KeyExchangeRegistry keyExchangeRegistry)
        {
            _serviceProvider = serviceProvider;
            _keyExchangeRegistry = keyExchangeRegistry;
        }
        
        public IKeyExchange Create(TLSKeyExchange keyExchange)
        {
            return _keyExchangeRegistry.Resolve(_serviceProvider, keyExchange);
        }

        public bool IsSupported(TLSKeyExchange keyExchange)
        {
            return _keyExchangeRegistry.IsSupported(keyExchange);
        }
    }
}