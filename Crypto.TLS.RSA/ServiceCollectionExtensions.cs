using Crypto.RSA.Encryption;
using Crypto.TLS.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.RSA
{
    public static class ServiceCollectionExtensions
    {
        public static void AddRSAKeyExchange(this IServiceCollection services)
        {           
            services.RegisterSignatureAlgorithms<RSASignatureCipher>(RSAIdentifiers.RSASig);
            services.RegisterSignatureCipherParameterFactory<RSACipherParameterFactory>(RSAIdentifiers.RSASig);
            services.RegisterKeyExchange<RSAKeyExchange>(RSAIdentifiers.RSAKex);
        }
    }
}
