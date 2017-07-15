using System;
using System.Linq;
using Crypto.Certificates;
using Crypto.TLS.Config;
using Crypto.TLS.Services;
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

        public TLSVersion DecideVersion(TLSVersion maxSupportedVersion)
        {
            // TODO handle if client doesn't support it
            return TLSVersion.TLS1_2;
        }

        public CipherSuite DecideCipherSuite(CipherSuite[] supportedCipherSuites)
        {
            // TODO handle if client doesn't support any
            return supportedCipherSuites.First(x => _serviceProvider.IsCipherSuiteSupported(x));
        }

        public CompressionMethod DecideCompression(CompressionMethod[] supportedCompressionMethods)
        {
            // TODO handle if client doesn't support it
            return CompressionMethod.Null;
        }

        public X509Certificate[] DecideCertificateChain()
        {
            var certificateManager = _serviceProvider.GetRequiredService<CertificateManager>();

            foreach (var certificate in certificateManager.GetAllCertificates())
            {
                if (IsSuitable(certificate))
                {
                    // TODO build actual chain
                    return new[]
                    {
                        certificate
                    };
                }
            }
            
            throw new InvalidOperationException("No suitable certificates found");
        }

        private bool IsSuitable(X509Certificate certificate)
        {
            // TODO SNI
            // TODO Compatible with signature

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