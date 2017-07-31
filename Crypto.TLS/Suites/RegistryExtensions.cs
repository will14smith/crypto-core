using System;
using Crypto.Core.Encryption;
using Crypto.Core.Hashing;
using Crypto.Core.Registry;
using Crypto.Core.Signing;
using Crypto.TLS.Identifiers;
using Crypto.TLS.KeyExchanges;
using Crypto.TLS.Suites.Parameters;
using Crypto.TLS.Suites.Registries;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.Suites
{
    public static class RegistryExtensions
    {
        public static IServiceCollection RegisterCipherSuite(
            this IServiceCollection serviceCollection,
            CipherSuite suite,
            TLSCipherAlgorithm cipher,
            TLSHashAlgorithm digest,
            TLSSignatureAlgorithm signature,
            TLSKeyExchange exchange)
        {
            return serviceCollection.Update<CipherSuitesRegistry>(prev =>
            {
                prev = prev ?? new CipherSuitesRegistry();

                prev.Register(
                    suite: suite,
                    cipher: cipher,
                    digest: digest,
                    signature: signature,
                    exchange: exchange);

                return prev;
            });
        }

        public static IServiceCollection RegisterPRFHash(
            this IServiceCollection serviceCollection,
            TLSHashAlgorithm digest,
            TLSHashAlgorithm prfDigest)
        {
            return serviceCollection.Update<PRFHashRegistry>(prev =>
            {
                prev = prev ?? new PRFHashRegistry();

                prev.Register(digest, () => prfDigest);

                return prev;
            });
        }

        public static IServiceCollection RegisterCipherAlgorithm<T>(this IServiceCollection serviceCollection, TLSCipherAlgorithm cipherAlgorithm)
            where T : class, ICipher, new()
        {
            return serviceCollection.Update<CipherAlgorithmRegistry>(prev =>
            {
                prev = prev ?? new CipherAlgorithmRegistry();

                prev.Register(cipherAlgorithm, () => new T());

                return prev;
            });
        }
        public static IServiceCollection RegisterCipherAlgorithm(this IServiceCollection serviceCollection, TLSCipherAlgorithm cipherAlgorithm, Func<ICipher> factory)
        {
            return serviceCollection.Update<CipherAlgorithmRegistry>(prev =>
            {
                prev = prev ?? new CipherAlgorithmRegistry();

                prev.Register(cipherAlgorithm, factory);

                return prev;
            });
        }

        public static IServiceCollection RegisterCipherParameterFactory<T>(this IServiceCollection serviceCollection, TLSCipherAlgorithm cipherAlgorithm)
            where T : class, ICipherParameterFactory
        {
            serviceCollection.AddTransient<T>();

            return serviceCollection.Update<CipherParameterFactoryRegistry>(prev =>
            {
                prev = prev ?? new CipherParameterFactoryRegistry();

                prev.Register(cipherAlgorithm, sp => sp.GetRequiredService<T>());

                return prev;
            });
        }

        public static IServiceCollection RegisterHashAlgorithm<T>(this IServiceCollection serviceCollection, TLSHashAlgorithm hashAlgorithm)
            where T : class, IDigest, new()
        {
            return serviceCollection.Update<HashAlgorithmRegistry>(prev =>
            {
                prev = prev ?? new HashAlgorithmRegistry();

                prev.Register(hashAlgorithm, () => new T());

                return prev;
            });
        }
        public static IServiceCollection RegisterHashAlgorithm(this IServiceCollection serviceCollection, TLSHashAlgorithm hashAlgorithm, Func<IDigest> factory)
        {
            return serviceCollection.Update<HashAlgorithmRegistry>(prev =>
            {
                prev = prev ?? new HashAlgorithmRegistry();

                prev.Register(hashAlgorithm, factory);

                return prev;
            });
        }

        public static IServiceCollection RegisterSignatureAlgorithms<T>(this IServiceCollection serviceCollection, TLSSignatureAlgorithm signatureAlgorithm)
            where T : class, ISignatureCipher, new()
        {
            return serviceCollection.Update<SignatureAlgorithmsRegistry>(prev =>
            {
                prev = prev ?? new SignatureAlgorithmsRegistry();

                prev.Register(signatureAlgorithm, () => new T());

                return prev;
            });
        }
        public static IServiceCollection RegisterSignatureAlgorithms(this IServiceCollection serviceCollection, TLSSignatureAlgorithm signatureAlgorithm, Func<ISignatureCipher> factory)
        {
            return serviceCollection.Update<SignatureAlgorithmsRegistry>(prev =>
            {
                prev = prev ?? new SignatureAlgorithmsRegistry();

                prev.Register(signatureAlgorithm, factory);

                return prev;
            });
        }

        public static IServiceCollection RegisterSignatureCipherParameterFactory<T>(this IServiceCollection serviceCollection, TLSSignatureAlgorithm signatureAlgorithm)
            where T : class, ICipherParameterFactory
        {
            serviceCollection.AddTransient<T>();

            return serviceCollection.Update<SignatureCipherParameterFactoryRegistry>(prev =>
            {
                prev = prev ?? new SignatureCipherParameterFactoryRegistry();

                prev.Register(signatureAlgorithm, sp => sp.GetRequiredService<T>());

                return prev;
            });
        }
        
        public static IServiceCollection RegisterKeyExchange<T>(this IServiceCollection serviceCollection, TLSKeyExchange keyExchange)
            where T : class, IKeyExchange
        {
            serviceCollection.AddTransient<T>();

            return serviceCollection.Update<KeyExchangeRegistry>(prev =>
            {
                prev = prev ?? new KeyExchangeRegistry();

                prev.Register(keyExchange, sp => sp.GetRequiredService<T>());

                return prev;
            });
        }

    }
}
