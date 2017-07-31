using Crypto.Certificates.Services;
using Crypto.Core.Randomness;
using Crypto.EC.Encryption;
using Crypto.TLS.EC.Config;
using Crypto.TLS.EC.Curves;
using Crypto.TLS.EC.Extensions;
using Crypto.TLS.EC.KeyExchanges;
using Crypto.TLS.EC.Keys;
using Crypto.TLS.EC.Services;
using Crypto.TLS.Extensions;
using Crypto.TLS.Suites;
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
                // TODO get IRandom from ServiceProvider
                .RegisterSignatureAlgorithms(ECIdentifiers.ECDSA, () => new ECDSA(new DefaultRandomGenerator()))
                .RegisterSignatureCipherParameterFactory<ECDSACipherParameterFactory>(ECIdentifiers.ECDSA);

            services
                .RegisterKeyExchange<ECDHKeyExchange>(ECIdentifiers.ECDH)
                .RegisterKeyExchange<ECDHEKeyExchange>(ECIdentifiers.ECDHE)
                .AddScoped<ECDHExchangeConfig>();

            var namedCurves = CreateNamedCurvesRegistry();
            services.AddSingleton(namedCurves);

            services
                .RegisterPublicKeyReader(ECIdentifiers.ECPublickey, () => new ECKeyReader(namedCurves))
                .RegisterPrivateKeyReader(ECIdentifiers.ECPublickey, () => new ECKeyReader(namedCurves));
        }

        private static NamedCurvesRegistry CreateNamedCurvesRegistry()
        {
            var namedCurves = new NamedCurvesRegistry();

            namedCurves.Register(Secp256K1.Id, Secp256K1.OID, Secp256K1.Parameters);
            namedCurves.Register(Sect283K1.Id, Sect283K1.OID, Sect283K1.Parameters);

            return namedCurves;
        }
    }
}
