using System;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.Suites.Parameters
{
    public class SignatureCipherParameterFactoryProvider : ISignatureCipherParameterFactoryProvider
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly SignatureCipherParameterFactoryRegistry _signatureCipherParameterFactoryRegistry;

        public SignatureCipherParameterFactoryProvider(
            IServiceProvider serviceProvider,
            SignatureCipherParameterFactoryRegistry signatureCipherParameterFactoryRegistry)
        {
            _serviceProvider = serviceProvider;
            _signatureCipherParameterFactoryRegistry = signatureCipherParameterFactoryRegistry;
        }

        public ICipherParameterFactory Create(TLSSignatureAlgorithm algorithm)
        {
            return _signatureCipherParameterFactoryRegistry.Resolve(_serviceProvider, algorithm);
        }

        public bool IsSupported(TLSSignatureAlgorithm algorithm)
        {
            return _signatureCipherParameterFactoryRegistry.IsSupported(algorithm);
        }
    }
}