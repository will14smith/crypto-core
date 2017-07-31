using System;
using Crypto.ASN1;
using Crypto.Certificates.Keys;
using Crypto.Core.Registry;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.Certificates.Services
{
    public static class RegistryExtensions
    {
        public static IServiceCollection RegisterPublicKeyReader<T>(this IServiceCollection serviceCollection, ASN1ObjectIdentifier algorithm)
            where T : class, IPublicKeyReader, new()
        {
            return serviceCollection.Update<PublicKeyReaderRegistry>(prev =>
            {
                prev = prev ?? new PublicKeyReaderRegistry();

                prev.Register(algorithm, () => new T());

                return prev;
            });
        }
        public static IServiceCollection RegisterPublicKeyReader<T>(this IServiceCollection serviceCollection, ASN1ObjectIdentifier algorithm, Func<T> factory)
            where T : class, IPublicKeyReader
        {
            return serviceCollection.Update<PublicKeyReaderRegistry>(prev =>
            {
                prev = prev ?? new PublicKeyReaderRegistry();

                prev.Register(algorithm, factory);

                return prev;
            });
        }

        public static IServiceCollection RegisterPrivateKeyReader<T>(this IServiceCollection serviceCollection, ASN1ObjectIdentifier algorithm)
            where T : class, IPrivateKeyReader, new()
        {
            return serviceCollection.Update<PrivateKeyReaderRegistry>(prev =>
            {
                prev = prev ?? new PrivateKeyReaderRegistry();

                prev.Register(algorithm, () => new T());

                return prev;
            });
        }
        public static IServiceCollection RegisterPrivateKeyReader<T>(this IServiceCollection serviceCollection, ASN1ObjectIdentifier algorithm, Func<T> factory)
            where T : class, IPrivateKeyReader
        {
            return serviceCollection.Update<PrivateKeyReaderRegistry>(prev =>
            {
                prev = prev ?? new PrivateKeyReaderRegistry();

                prev.Register(algorithm, factory);

                return prev;
            });
        }
    }
}