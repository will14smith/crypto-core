using Crypto.AES;
using Crypto.Core.Encryption.Adapters;
using Crypto.Core.Encryption.BlockModes;
using Crypto.TLS.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.AES
{
    public static class ServiceCollectionExtensions
    {
        public static void AddAES(this IServiceCollection services)
        {
            services.RegisterCipherAlgorithm(AESIdentifiers.AES128_CBC, _ => new BlockCipherAdapter(new CBCBlockCipher(new AESCipher(128))));
            services.RegisterCipherAlgorithm(AESIdentifiers.AES256_CBC, _ => new BlockCipherAdapter(new CBCBlockCipher(new AESCipher(256))));
            
            services.RegisterCipherParameterFactory<AESCipherParameterFactory>(AESIdentifiers.AES128_CBC);
            services.RegisterCipherParameterFactory<AESCipherParameterFactory>(AESIdentifiers.AES256_CBC);
        }
    }
}
