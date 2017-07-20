using System;
using System.Collections.Generic;
using System.Linq;
using Crypto.Core.Encryption;
using Crypto.Core.Hashing;
using Crypto.Core.Signing;
using Crypto.TLS.Identifiers;
using Crypto.TLS.KeyExchanges;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.Services
{
    public static class ServiceProviderExtensions
    {
        public static ICipher ResolveCipherAlgorithm(this IServiceProvider serviceProvider, CipherSuite suite)
        {
            var cipherAlgorithm = serviceProvider.GetRequiredService<CipherSuiteRegistry>().ResolveCipherAlgorithm(suite);
            return serviceProvider.GetRequiredService<CipherAlgorithmRegistry>().Resolve(serviceProvider, cipherAlgorithm);
        }
        public static ICipherParameterFactory ResolveCipherParameterFactory(this IServiceProvider serviceProvider, CipherSuite suite)
        {
            var cipherAlgorithm = serviceProvider.GetRequiredService<CipherSuiteRegistry>().ResolveCipherAlgorithm(suite);
            return serviceProvider.GetRequiredService<CipherParameterFactoryRegistry>().Resolve(serviceProvider, cipherAlgorithm);
        }

        public static IDigest ResolveHashAlgorithm(this IServiceProvider serviceProvider, TLSHashAlgorithm hashAlgorithm)
        {
            return serviceProvider.GetRequiredService<HashAlgorithmRegistry>().Resolve(serviceProvider, hashAlgorithm);
        }
        public static IDigest ResolveHashAlgorithm(this IServiceProvider serviceProvider, CipherSuite suite)
        {
            var hashAlgorithm = serviceProvider.GetRequiredService<CipherSuiteRegistry>().ResolveHashAlgorithm(suite);
            return serviceProvider.ResolveHashAlgorithm(hashAlgorithm);
        }
        public static IDigest ResolvePRFHash(this IServiceProvider serviceProvider, CipherSuite suite)
        {
            var hashAlgorithm = serviceProvider.GetRequiredService<CipherSuiteRegistry>().ResolveHashAlgorithm(suite);
            var prfHashAlgorithm = serviceProvider.GetRequiredService<PRFHashRegistry>().Resolve(serviceProvider, hashAlgorithm);
            return serviceProvider.GetRequiredService<HashAlgorithmRegistry>().Resolve(serviceProvider, prfHashAlgorithm);
        }

        public static ISignatureCipher ResolveSignatureAlgorithm(this IServiceProvider serviceProvider, TLSSignatureAlgorithm signatureAlgorithm)
        {
            return serviceProvider.GetRequiredService<SignatureAlgorithmsRegistry>().Resolve(serviceProvider, signatureAlgorithm);
        }
        public static ICipherParameterFactory ResolveSignatureCipherParameterFactory(this IServiceProvider serviceProvider, TLSSignatureAlgorithm signatureAlgorithm)
        {
            return serviceProvider.GetRequiredService<SignatureCipherParameterFactoryRegistry>().Resolve(serviceProvider, signatureAlgorithm);
        }
        public static ISignatureCipher ResolveSignatureAlgorithm(this IServiceProvider serviceProvider, CipherSuite suite)
        {
            var signatureAlgorithm = serviceProvider.GetRequiredService<CipherSuiteRegistry>().ResolveSignatureAlgorithm(suite);
            return serviceProvider.ResolveSignatureAlgorithm(signatureAlgorithm);
        }
        public static ICipherParameterFactory ResolveSignatureCipherParameterFactory(this IServiceProvider serviceProvider, CipherSuite suite)
        {
            var signatureAlgorithm = serviceProvider.GetRequiredService<CipherSuiteRegistry>().ResolveSignatureAlgorithm(suite);
            return serviceProvider.ResolveSignatureCipherParameterFactory(signatureAlgorithm);
        }

        public static IKeyExchange ResolveKeyExchange(this IServiceProvider serviceProvider, CipherSuite suite)
        {
            var keyExchange = serviceProvider.GetRequiredService<CipherSuiteRegistry>().ResolveKeyExchange(suite);
            return serviceProvider.GetRequiredService<KeyExchangeRegistry>().Resolve(serviceProvider, keyExchange);
        }

        public static IReadOnlyCollection<CipherSuite> GetAllSupportedSuites(this IServiceProvider serviceProvider)
        {
            return serviceProvider.GetRequiredService<CipherSuiteRegistry>()
                .GetAll()
                .Where(x => IsCipherSuiteSupported(serviceProvider, x))
                // TODO allow user to specify ordering
                .OrderByDescending(x => x)
                .ToList();
        }

        public static bool IsCipherSuiteSupported(this IServiceProvider serviceProvider, CipherSuite suite)
        {
            var cipherSuiteRegistry = serviceProvider.GetRequiredService<CipherSuiteRegistry>();

            if (!cipherSuiteRegistry.IsSupported(suite)) return false;

            if (!serviceProvider.GetRequiredService<CipherAlgorithmRegistry>().IsSupported(cipherSuiteRegistry.ResolveCipherAlgorithm(suite))) return false;
            if (!serviceProvider.GetRequiredService<CipherParameterFactoryRegistry>().IsSupported(cipherSuiteRegistry.ResolveCipherAlgorithm(suite))) { return false; }
            if (!serviceProvider.GetRequiredService<HashAlgorithmRegistry>().IsSupported(cipherSuiteRegistry.ResolveHashAlgorithm(suite))) return false;
            if (!serviceProvider.GetRequiredService<PRFHashRegistry>().IsSupported(cipherSuiteRegistry.ResolveHashAlgorithm(suite))) return false;
            if (!serviceProvider.GetRequiredService<SignatureAlgorithmsRegistry>().IsSupported(cipherSuiteRegistry.ResolveSignatureAlgorithm(suite))) return false;
            if (!serviceProvider.GetRequiredService<SignatureCipherParameterFactoryRegistry>().IsSupported(cipherSuiteRegistry.ResolveSignatureAlgorithm(suite))) return false;
            if (!serviceProvider.GetRequiredService<KeyExchangeRegistry>().IsSupported(cipherSuiteRegistry.ResolveKeyExchange(suite))) return false;

            return true;
        }

    }
}
