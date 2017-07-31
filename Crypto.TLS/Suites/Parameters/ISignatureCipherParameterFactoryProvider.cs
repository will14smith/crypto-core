using Crypto.TLS.Identifiers;

namespace Crypto.TLS.Suites.Parameters
{
    public interface ISignatureCipherParameterFactoryProvider
    {
        ICipherParameterFactory Create(TLSSignatureAlgorithm algorithm);
        bool IsSupported(TLSSignatureAlgorithm algorithm);
    }
}