using Crypto.Certificates.Services;
using Crypto.TLS.DH.Config;
using Crypto.TLS.DH.KeyExchanges;
using Crypto.TLS.DH.Keys;
using Crypto.TLS.Services;
using Crypto.TLS.Suites;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.DH
{
    public static class ServiceCollectionExtensions
    {
        public static void AddDHKeyExchange(this IServiceCollection services, [CanBeNull] DHParameterConfig parameters = null)
        {
            services.AddTransient<DHServerKeyExchange>();
            services.AddTransient<DHClientKeyExchange>();
            services.AddTransient<DHEServerKeyExchange>();
            services.AddTransient<DHEClientKeyExchange>();

            services.RegisterKeyExchange<DHKeyExchange>(DHIdentifiers.DHKex);
            services.RegisterKeyExchange<DHEKeyExchange>(DHIdentifiers.DHEKex);
            services.RegisterPublicKeyReader<DHKeyReader>(DHIdentifiers.DHKeyAgreement);
            services.RegisterPrivateKeyReader<DHKeyReader>(DHIdentifiers.DHKeyAgreement);

            if (parameters != null)
            {
                services.AddScoped(_ => new DHParameterConfig(parameters.P, parameters.G));
            }
            else
            {
                services.AddScoped<DHParameterConfig>();
            }

            services.AddScoped<DHExchangeConfig>();
        }
    }
}
