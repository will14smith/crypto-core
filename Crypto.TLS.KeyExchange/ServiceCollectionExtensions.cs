using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.KeyExchange
{
    public static class ServiceCollectionExtensions
    {
        public static void AddKeyExchange(this IServiceCollection services)
        {
            services.AddTransient<MasterSecretCalculator>();
        }
    }
}
