using Crypto.Core.Registry;
using Crypto.Core.Signing;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.Suites.Registries
{
    public class SignatureAlgorithmsRegistry : BaseRegistry<TLSSignatureAlgorithm, ISignatureCipher>
    {
        public SignatureAlgorithmsRegistry()
        {
            Register(TLSSignatureAlgorithm.Anonymous, () => new NullSignatureCipher());
        }
    }
}