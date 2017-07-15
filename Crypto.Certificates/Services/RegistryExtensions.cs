using Crypto.ASN1;
using Crypto.Certificates.Keys;
using Crypto.Core.Registry;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.Certificates.Services
{
    public static class RegistryExtensions
    {
        public static IServiceCollection RegisterPublicKeyReader<T>(this IServiceCollection serviceCollection, ASN1ObjectIdentifier algorithm)
            where T : class, IPublicKeyReader
        {
            serviceCollection.AddTransient<T>();
            
            return serviceCollection.Update<PublicKeyReaderRegistry>(prev =>
            {
                prev = prev ?? new PublicKeyReaderRegistry();

                prev.Register(algorithm, sp => sp.GetRequiredService<T>());

                return prev;
            });
        }

        public static IServiceCollection RegisterPrivateKeyReader<T>(this IServiceCollection serviceCollection, ASN1ObjectIdentifier algorithm)
            where T : class, IPrivateKeyReader
        {
            serviceCollection.AddTransient<T>();

            return serviceCollection.Update<PrivateKeyReaderRegistry>(prev =>
            {
                prev = prev ?? new PrivateKeyReaderRegistry();

                prev.Register(algorithm, sp => sp.GetRequiredService<T>());

                return prev;
            });
        }
    }
}