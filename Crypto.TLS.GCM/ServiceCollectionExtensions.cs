using Crypto.AES;
using Crypto.Core.Encryption.Adapters;
using Crypto.GCM;
using Crypto.TLS.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.GCM
{
    public static class ServiceCollectionExtensions
    {
        public static void AddGCM(this IServiceCollection services)
        {
            services.RegisterCipherAlgorithm(GCMIdentifiers.AES128_GCM, _ => new AEADCipherAdapter(new GCMCipher(new AESCipher(128))));
            services.RegisterCipherAlgorithm(GCMIdentifiers.AES256_GCM, _ => new AEADCipherAdapter(new GCMCipher(new AESCipher(256))));
            
            services.RegisterCipherParameterFactory<AESCipherParameterFactory>(GCMIdentifiers.AES128_GCM);
            services.RegisterCipherParameterFactory<AESCipherParameterFactory>(GCMIdentifiers.AES256_GCM);
        }
    }
}
