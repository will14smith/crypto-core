using Crypto.Certificates.Services;
using Crypto.Core.Registry;
using Crypto.EC.Encryption;
using Crypto.TLS.EC.Config;
using Crypto.TLS.EC.Curves;
using Crypto.TLS.EC.Extensions;
using Crypto.TLS.EC.KeyExchanges;
using Crypto.TLS.EC.Keys;
using Crypto.TLS.EC.Services;
using Crypto.TLS.Extensions;
using Crypto.TLS.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.EC
{
    public static class ServiceCollectionExtensions
    {
        public static void AddEC(this IServiceCollection services)
        {
            services
                .RegisterExtension<SupportedGroupsExtension>(ECIdentifiers.SupportedGroups)
                .AddScoped<SupportedGroupsConfig>();
            services
                .RegisterExtension<ECPointFormatsExtension>(ECIdentifiers.ECPointFormats)
                .AddScoped<ECPointFormatsConfig>();

            services
                .RegisterSignatureAlgorithms<ECDSA>(ECIdentifiers.ECDSA)
                .RegisterSignatureCipherParameterFactory<ECDSACipherParameterFactory>(ECIdentifiers.ECDSA);

            services.RegisterKeyExchange<ECDHEKeyExchange>(ECIdentifiers.ECDHE)
                .AddScoped<ECDHExchangeConfig>();

            services
                .RegisterPublicKeyReader<ECKeyReader>(ECIdentifiers.ECPublickey)
                .RegisterPrivateKeyReader<ECKeyReader>(ECIdentifiers.ECPublickey);

            services.Update<NamedCurvesRegistry>(prev =>
            {
                prev = prev ?? new NamedCurvesRegistry();
                AddNamedCurves(prev);
                return prev;
            });
        }

        private static void AddNamedCurves(this NamedCurvesRegistry namedCurves)
        {
            namedCurves.Register(Secp256K1.Id, Secp256K1.OID, Secp256K1.Parameters);
        }
    }
}
