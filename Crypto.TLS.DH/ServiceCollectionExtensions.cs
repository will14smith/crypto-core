using Crypto.Certificates.Services;
using Crypto.TLS.DH.Config;
using Crypto.TLS.DH.KeyExchanges;
using Crypto.TLS.DH.Keys;
using Crypto.TLS.KeyExchange;
using Crypto.TLS.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.DH
{
    public static class ServiceCollectionExtensions
    {
        public static void AddDHKeyExchange(this IServiceCollection services, DHParameterConfig parameters)
        {
            services.AddKeyExchange();

            services.RegisterKeyExchange<DHKeyExchange>(DHIdentifiers.DHKex);
            services.RegisterKeyExchange<DHEKeyExchange>(DHIdentifiers.DHEKex);
            services.RegisterPublicKeyReader<DHKeyReader>(DHIdentifiers.DHKeyAgreement);
            services.RegisterPrivateKeyReader<DHKeyReader>(DHIdentifiers.DHKeyAgreement);
            
            services.AddSingleton(parameters);
            services.AddScoped<DHExchangeConfig>();
            services.AddTransient<MasterSecretCalculator>();
        }
    }
}
