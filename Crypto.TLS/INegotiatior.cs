using Crypto.Certificates;

namespace Crypto.TLS
{
    public interface INegotiatior
    {
        TLSVersion DecideVersion(TLSVersion maxSupportedVersion);
        CipherSuite DecideCipherSuite(CipherSuite[] supportedCipherSuites);
        CompressionMethod DecideCompression(CompressionMethod[] supportedCompressionMethods);

        X509Certificate[] DecideCertificateChain();
    }
}