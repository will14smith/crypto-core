using Crypto.TLS.Identifiers;

namespace Crypto.TLS.Suites.Parameters
{
    public interface ICipherParameterFactoryProvider
    {
        ICipherParameterFactory Create(TLSCipherAlgorithm algorithm);
        bool IsSupported(TLSCipherAlgorithm algorithm);
    }
}