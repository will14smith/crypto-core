using System.Linq;
using Crypto.Certificates;
using Crypto.TLS.Config;
using Crypto.TLS.Suites.Providers;
using Crypto.Utils;

namespace Crypto.TLS
{
    public class DefaultNegotiatior : INegotiatior
    {
        private readonly ICipherSuitesProvider _cipherSuitesProvider;
        private readonly CertificateManager _certificateManager;
        private readonly CipherSuiteConfig _cipherSuiteConfig;

        public DefaultNegotiatior(
            ICipherSuitesProvider cipherSuitesProvider,
            CertificateManager certificateManager,
            CipherSuiteConfig cipherSuiteConfig)
        {
            _cipherSuitesProvider = cipherSuitesProvider;
            _certificateManager = certificateManager;
            _cipherSuiteConfig = cipherSuiteConfig;
        }

        public Option<TLSVersion> DecideVersion(TLSVersion maxSupportedVersion)
        {
            if (maxSupportedVersion < TLSVersion.TLS1_2)
            {
                return Option.None<TLSVersion>();
            }

            return Option.Some(TLSVersion.TLS1_2);

        }

        public Option<CipherSuite> DecideCipherSuite(CipherSuite[] supportedCipherSuites)
        {
            foreach (var x in supportedCipherSuites)
            {
                if (_cipherSuitesProvider.IsSupported(x))
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
            foreach (var certificate in _certificateManager.GetAllCertificates())
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

            var cipherSuite = _cipherSuiteConfig.CipherSuite;

            var keyExchange = _cipherSuitesProvider.ResolveKeyExchange(cipherSuite);
            return keyExchange.IsCompatible(cipherSuite, certificate);
        }
    }
}