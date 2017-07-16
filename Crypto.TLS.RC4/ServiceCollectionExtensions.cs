using Crypto.RC4;
using Crypto.TLS.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.RC4
{
    public static class ServiceCollectionExtensions
    {
        public static void AddRC4(this IServiceCollection services)
        {
            services.RegisterCipherAlgorithm(RC4Identifiers.RC4_128, _ => new RC4Cipher(128));
            
            services.RegisterCipherParameterFactory<RC4CipherParameterFactory>(RC4Identifiers.RC4_128);
        }
    }
}
