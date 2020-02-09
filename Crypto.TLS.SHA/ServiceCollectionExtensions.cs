using Crypto.SHA;
using Crypto.TLS.Services;
using Crypto.TLS.Suites;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.SHA
{
    public static class ServiceCollectionExtensions
    {
        public static void AddSHA(this IServiceCollection services)
        {
            services.RegisterHashAlgorithm<SHA1Digest>(SHAIdentifiers.SHA1);
            services.RegisterHashAlgorithm(SHAIdentifiers.SHA256, () => new SHA256Digest(SHA256Digest.Mode.SHA256));
            services.RegisterHashAlgorithm(SHAIdentifiers.SHA384, () => new SHA512Digest(SHA512Digest.Mode.SHA384));
            services.RegisterHashAlgorithm(SHAIdentifiers.SHA512, () => new SHA512Digest(SHA512Digest.Mode.SHA512));

            services.RegisterPRFHash(SHAIdentifiers.SHA1, SHAIdentifiers.SHA256);
            services.RegisterPRFHash(SHAIdentifiers.SHA256, SHAIdentifiers.SHA256);
            services.RegisterPRFHash(SHAIdentifiers.SHA384, SHAIdentifiers.SHA384);
            services.RegisterPRFHash(SHAIdentifiers.SHA512, SHAIdentifiers.SHA512);
        }
    }
}
