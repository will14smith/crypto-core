using System;
using Crypto.Core.Signing;
using Crypto.TLS.Config;
using Crypto.TLS.Identifiers;
using Crypto.TLS.Services;
using Crypto.Utils.IO;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS
{
    public static class ServiceProviderExtensions
    {
        public static SignedStream CreateSignedStream(this IServiceProvider serviceProvider, EndianBinaryWriter baseWriter, TLSHashAlgorithm hashAlgorithm, TLSSignatureAlgorithm signatureAlgorithm)
        {
            var signature = serviceProvider.ResolveSignatureAlgorithm(signatureAlgorithm);
            var signatureCipherFactory = serviceProvider.ResolveSignatureCipherParameterFactory(signatureAlgorithm);
            var digest = serviceProvider.ResolveHashAlgorithm(hashAlgorithm);

            var endConfig = serviceProvider.GetRequiredService<EndConfig>();

            signature.Init(signatureCipherFactory.Create(endConfig.End, ConnectionDirection.Write));

            return new SignedStream(baseWriter.BaseStream, signature, digest);
        }

    }
}