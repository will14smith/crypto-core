using Crypto.Core.Encryption;
using Crypto.Core.Hashing;
using Crypto.Core.Signing;
using Crypto.TLS.KeyExchanges;
using Crypto.TLS.Suites.Parameters;

namespace Crypto.TLS.Suites.Providers
{
    public interface ICipherSuitesProvider
    {
        bool IsSupported(CipherSuite suite);
        
        ICipher ResolveCipherAlgorithm(CipherSuite suite);
        IDigest ResolveHashAlgorithm(CipherSuite suite);
        IDigest ResolvePRFHash(CipherSuite suite);
        ISignatureCipher ResolveSignatureAlgorithm(CipherSuite suite);
        IKeyExchange ResolveKeyExchange(CipherSuite suite);

        ICipherParameterFactory ResolveCipherParameterFactory(CipherSuite suite);
        ICipherParameterFactory ResolveSignatureCipherParameterFactory(CipherSuite suite);
    }
}