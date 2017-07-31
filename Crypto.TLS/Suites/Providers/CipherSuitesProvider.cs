using Crypto.Core.Encryption;
using Crypto.Core.Hashing;
using Crypto.Core.Signing;
using Crypto.TLS.KeyExchanges;
using Crypto.TLS.Suites.Parameters;
using Crypto.TLS.Suites.Registries;

namespace Crypto.TLS.Suites.Providers
{
    internal class CipherSuitesProvider : ICipherSuitesProvider
    {
        private readonly CipherSuitesRegistry _registry;

        private readonly CipherAlgorithmRegistry _cipherAlgorithmRegistry;
        private readonly HashAlgorithmRegistry _hashAlgorithmRegistry;
        private readonly PRFHashRegistry _prfHashRegistry;
        private readonly SignatureAlgorithmsRegistry _signatureAlgorithmsRegistry;
        private readonly IKeyExchangeProvider _keyExchangeProvider;

        private readonly ICipherParameterFactoryProvider _cipherParameterFactoryProvider;
        private readonly ISignatureCipherParameterFactoryProvider _signatureCipherParameterFactoryProvider;

        public CipherSuitesProvider(
            CipherSuitesRegistry registry,

            CipherAlgorithmRegistry cipherAlgorithmRegistry,
            HashAlgorithmRegistry hashAlgorithmRegistry,
            PRFHashRegistry prfHashRegistry,
            SignatureAlgorithmsRegistry signatureAlgorithmsRegistry,
            IKeyExchangeProvider keyExchangeProvider,

            ICipherParameterFactoryProvider cipherParameterFactoryProvider,
            ISignatureCipherParameterFactoryProvider signatureCipherParameterFactoryProvider)
        {
            _registry = registry;

            _cipherAlgorithmRegistry = cipherAlgorithmRegistry;
            _hashAlgorithmRegistry = hashAlgorithmRegistry;
            _prfHashRegistry = prfHashRegistry;
            _signatureAlgorithmsRegistry = signatureAlgorithmsRegistry;
            _keyExchangeProvider = keyExchangeProvider;

            _cipherParameterFactoryProvider = cipherParameterFactoryProvider;
            _signatureCipherParameterFactoryProvider = signatureCipherParameterFactoryProvider;
        }

        public bool IsSupported(CipherSuite suite)
        {
            if (!_registry.IsSupported(suite)) return false;

            if (!_cipherAlgorithmRegistry.IsSupported(_registry.MapCipherAlgorithm(suite))) return false;
            if (!_cipherParameterFactoryProvider.IsSupported(_registry.MapCipherAlgorithm(suite))) { return false; }
            if (!_hashAlgorithmRegistry.IsSupported(_registry.MapHashAlgorithm(suite))) return false;
            if (!_prfHashRegistry.IsSupported(_registry.MapHashAlgorithm(suite))) return false;
            if (!_signatureAlgorithmsRegistry.IsSupported(_registry.MapSignatureAlgorithm(suite))) return false;
            if (!_signatureCipherParameterFactoryProvider.IsSupported(_registry.MapSignatureAlgorithm(suite))) return false;
            if (!_keyExchangeProvider.IsSupported(_registry.MapKeyExchange(suite))) return false;

            return true;
        }

        public ICipher ResolveCipherAlgorithm(CipherSuite suite)
        {
            return _cipherAlgorithmRegistry.Resolve(_registry.MapCipherAlgorithm(suite));
        }
        public IDigest ResolveHashAlgorithm(CipherSuite suite)
        {
            return _hashAlgorithmRegistry.Resolve(_registry.MapHashAlgorithm(suite));
        }
        public IDigest ResolvePRFHash(CipherSuite suite)
        {
            var hashAlgorithm = _registry.MapHashAlgorithm(suite);
            var prfHashAlgorithm = _prfHashRegistry.Resolve(hashAlgorithm);
            return _hashAlgorithmRegistry.Resolve(prfHashAlgorithm);
        }
        public ISignatureCipher ResolveSignatureAlgorithm(CipherSuite suite)
        {
            return _signatureAlgorithmsRegistry.Resolve(_registry.MapSignatureAlgorithm(suite));
        }
        public IKeyExchange ResolveKeyExchange(CipherSuite suite)
        {
            return _keyExchangeProvider.Create(_registry.MapKeyExchange(suite));
        }

        public ICipherParameterFactory ResolveCipherParameterFactory(CipherSuite suite)
        {
            return _cipherParameterFactoryProvider.Create(_registry.MapCipherAlgorithm(suite));
        }
        public ICipherParameterFactory ResolveSignatureCipherParameterFactory(CipherSuite suite)
        {
            return _signatureCipherParameterFactoryProvider.Create(_registry.MapSignatureAlgorithm(suite));
        }
    }
}
