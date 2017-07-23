using System;
using System.Linq;
using Crypto.Certificates;
using Crypto.TLS.Config;
using Crypto.TLS.Services;
using Crypto.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS
{
    public class DefaultNegotiatior : INegotiatior
    {
        private readonly IServiceProvider _serviceProvider;

        public DefaultNegotiatior(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public Option<TLSVersion> DecideVersion(TLSVersion maxSupportedVersion)
        {
            if (maxSupportedVersion != TLSVersion.TLS1_2)
            {
                return Option.None<TLSVersion>();
            }

            return Option.Some(TLSVersion.TLS1_2);
        }

        public Option<CipherSuite> DecideCipherSuite(CipherSuite[] supportedCipherSuites)
        {
            foreach (var x in supportedCipherSuites)
            {
                if (_serviceProvider.IsCipherSuiteSupported(x))
                    return Option.Some(x);
            }

            return Option.None<CipherSuite>();
        }

        public Option<CompressionMethod> DecideCompression(CompressionMethod[] supportedCompressionMethods)
        {
            if (!supportedCompressionMethods.Contains(CompressionMethod.Null))
            {
                return Option.None<CompressionMethod>();
            }

            return Option.Some(CompressionMethod.Null);

        }

        public Option<X509Certificate[]> DecideCertificateChain()
        {
            var certificateManager = _serviceProvider.GetRequiredService<CertificateManager>();

            foreach (var certificate in certificateManager.GetAllCertificates())
            {
                if (IsSuitable(certificate))
                {
                    // TODO build actual chain
                    return Option.Some(new[]
                    {
                        certificate
                    });
                }
            }

            return Option.None<X509Certificate[]>();
        }

        private bool IsSuitable(X509Certificate certificate)
        {
            // TODO SNI
            // TODO is compatible with signature_algorithms extn
            // TODO is compatible with signature

            var cipherSuite = _serviceProvider.GetRequiredService<CipherSuiteConfig>().CipherSuite;

            var keyExchange = _serviceProvider.ResolveKeyExchange(cipherSuite);
            if (!keyExchange.IsCompatible(cipherSuite, certificate))
            {
                return false;
            }

            return true;
        }
    }
}