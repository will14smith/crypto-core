using Crypto.EC.Encryption;
using Crypto.TLS.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.EC
{
    public static class ServiceCollectionExtensions
    {
        public static void AddEC(this IServiceCollection services)
        {
            services.RegisterSignatureAlgorithms<ECDSA>(ECIdentifiers.ECDSA);
            services.RegisterSignatureCipherParameterFactory<ECDSACipherParameterFactory>(ECIdentifiers.ECDSA);

            services.RegisterKeyExchange<ECDHEKeyExchange>(ECIdentifiers.ECDHE);
        }
    }
}
