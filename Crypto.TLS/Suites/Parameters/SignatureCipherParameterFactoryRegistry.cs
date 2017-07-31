using Crypto.Core.Registry;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.Suites.Parameters
{
    public class SignatureCipherParameterFactoryRegistry : BaseServiceRegistry<TLSSignatureAlgorithm, ICipherParameterFactory>
    {
    }
}