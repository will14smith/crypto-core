using Crypto.Core.Encryption;
using Crypto.Core.Registry;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.Services
{
    public class CipherAlgorithmRegistry : BaseRegistry<TLSCipherAlgorithm, ICipher>
    {
        public CipherAlgorithmRegistry()
        {
            Register(TLSCipherAlgorithm.Null, _ => new NullCipher());
        }
    }
}
