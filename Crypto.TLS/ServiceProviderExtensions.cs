using System;
using System.IO;
using System.Linq;
using Crypto.Core.Signing;
using Crypto.TLS.Config;
using Crypto.TLS.Extensions;
using Crypto.TLS.Identifiers;
using Crypto.TLS.Services;
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
            var cipherSuites = serviceProvider.GetRequiredService<CipherSuiteRegistry>();

            var hashAlgorithm = cipherSuites.ResolveHashAlgorithm(cipherSuiteConfig.CipherSuite);
            var signatureAlgorithm = cipherSuites.ResolveSignatureAlgorithm(cipherSuiteConfig.CipherSuite);

            return (hashAlgorithm, signatureAlgorithm);
        }

        public static SignedStream CreateSignedStream(this IServiceProvider serviceProvider, Stream stream, TLSHashAlgorithm hashAlgorithm, TLSSignatureAlgorithm signatureAlgorithm)
        {
            var signature = serviceProvider.ResolveSignatureAlgorithm(signatureAlgorithm);
            var signatureCipherFactory = serviceProvider.ResolveSignatureCipherParameterFactory(signatureAlgorithm);
            var digest = serviceProvider.ResolveHashAlgorithm(hashAlgorithm);

            var endConfig = serviceProvider.GetRequiredService<EndConfig>();

            signature.Init(signatureCipherFactory.Create(endConfig.End, ConnectionDirection.Write));

            return new SignedStream(stream, signature, digest);
        }

    }
}