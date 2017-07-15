using Crypto.Core.Encryption;
using Crypto.Core.Registry;
using Crypto.Core.Signing;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.Services
{
    public class SignatureAlgorithmsRegistry : BaseRegistry<TLSSignatureAlgorithm, ISignatureCipher>
    {
        public SignatureAlgorithmsRegistry()
        {
            Register(TLSSignatureAlgorithm.Anonymous, _ => new NullSignatureCipher());
        }
    }
}