using System;
using System.IO;
using System.Linq;
using Crypto.Core.Signing;
using Crypto.TLS.Config;
using Crypto.TLS.Extensions;
using Crypto.TLS.Identifiers;
using Crypto.TLS.Suites.Parameters;
using Crypto.TLS.Suites.Registries;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS
{
    public static class ServiceProviderExtensions
    {
        public static (TLSHashAlgorithm, TLSSignatureAlgorithm) GetSigningAlgorithms(this IServiceProvider serviceProvider)
        {
            var config = serviceProvider.GetRequiredService<SignatureAlgorithmsExtension.Config>();

            if (config.SupportedAlgorithms.Any())
            {
                return config.SupportedAlgorithms.First();
            }

            var cipherSuiteConfig = serviceProvider.GetRequiredService<CipherSuiteConfig>();
            var cipherSuites = serviceProvider.GetRequiredService<CipherSuitesRegistry>();

            var hashAlgorithm = cipherSuites.MapHashAlgorithm(cipherSuiteConfig.CipherSuite);
            var signatureAlgorithm = cipherSuites.MapSignatureAlgorithm(cipherSuiteConfig.CipherSuite);

            return (hashAlgorithm, signatureAlgorithm);
        }

        public static SignedStream CreateSignedStream(this IServiceProvider serviceProvider, Stream stream, TLSHashAlgorithm hashAlgorithm, TLSSignatureAlgorithm signatureAlgorithm)
        {
            var signatureRegistry = serviceProvider.GetRequiredService<SignatureAlgorithmsRegistry>();
            var signatureCipherParameterFactoryProvider = serviceProvider.GetRequiredService<ISignatureCipherParameterFactoryProvider>();
            var hashRegistry = serviceProvider.GetRequiredService<HashAlgorithmRegistry>();

            var signature = signatureRegistry.Resolve(signatureAlgorithm);
            var signatureCipherFactory = signatureCipherParameterFactoryProvider.Create(signatureAlgorithm);
            var digest = hashRegistry.Resolve(hashAlgorithm);

            var endConfig = serviceProvider.GetRequiredService<EndConfig>();

            signature.Init(signatureCipherFactory.Create(endConfig.End, ConnectionDirection.Write));

            return new SignedStream(stream, signature, digest);
        }

    }
}