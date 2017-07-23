using Crypto.Certificates;
using Crypto.Utils;

namespace Crypto.TLS
{
    public interface INegotiatior
    {
        Option<TLSVersion> DecideVersion(TLSVersion maxSupportedVersion);
        Option<CipherSuite> DecideCipherSuite(CipherSuite[] supportedCipherSuites);
        Option<CompressionMethod> DecideCompression(CompressionMethod[] supportedCompressionMethods);

        Option<X509Certificate[]> DecideCertificateChain();
    }
}