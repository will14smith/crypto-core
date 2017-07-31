using System;
using Crypto.TLS.Identifiers;
using Crypto.TLS.Suites.Registries;

namespace Crypto.TLS.Suites.Parameters
{
    public class CipherParameterFactoryProvider : ICipherParameterFactoryProvider
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly CipherParameterFactoryRegistry _cipherParameterFactoryRegistry;

        public CipherParameterFactoryProvider(
            IServiceProvider serviceProvider,
            CipherParameterFactoryRegistry cipherParameterFactoryRegistry)
        {
            _serviceProvider = serviceProvider;
            _cipherParameterFactoryRegistry = cipherParameterFactoryRegistry;
        }

        public ICipherParameterFactory Create(TLSCipherAlgorithm algorithm)
        {
            return _cipherParameterFactoryRegistry.Resolve(_serviceProvider, algorithm);
        }

        public bool IsSupported(TLSCipherAlgorithm algorithm)
        {
            return _cipherParameterFactoryRegistry.IsSupported(algorithm);
        }
    }
}