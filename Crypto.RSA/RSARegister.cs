using Crypto.Certificates.Services;
using Crypto.RSA.Keys;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.RSA
{
    public static class RSARegister
    {
        public static void AddRSAKeyReaders(this IServiceCollection services)
        {
            foreach (var identifier in RSAKeyReader.RSAIdentifiers)
            {
                services.RegisterPublicKeyReader<RSAKeyReader>(identifier);
                services.RegisterPrivateKeyReader<RSAKeyReader>(identifier);
            }
        }
    }
}
