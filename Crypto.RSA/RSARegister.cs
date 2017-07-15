using Crypto.Certificates.Services;
using Crypto.RSA.Keys;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.RSA
{
    public static class RSARegister
    {
        public static void AddRSAKeyReaders(this IServiceCollection services)
        {           
            services.RegisterPublicKeyReader<RSAKeyReader>(RSAKeyReader.RSAEncryption);
            services.RegisterPrivateKeyReader<RSAKeyReader>(RSAKeyReader.RSAEncryption);
        }
    }
}
