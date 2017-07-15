using System;
using System.Linq;
using Crypto.Certificates;
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
            // TODO SNI
            return new[]
            {
                _serviceProvider.GetRequiredService<CertificateManager>().GetDefaultCertificate()
            };
        }
    }
}