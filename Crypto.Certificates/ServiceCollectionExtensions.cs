using Crypto.Certificates.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.Certificates
{
    public static class ServiceCollectionExtensions
    {
        public static void AddCertificateManager(this IServiceCollection services)
        {
            services.AddSingleton<PublicKeyReaderRegistry>();
            services.AddSingleton<PrivateKeyReaderRegistry>();

            services.AddSingleton<CertificateManager>();
        }
    }
}
