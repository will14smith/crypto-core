using Crypto.Core.Hashing;
using Crypto.Core.Registry;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.Suites.Registries
{
    public class HashAlgorithmRegistry : BaseRegistry<TLSHashAlgorithm, IDigest>
    {
        public HashAlgorithmRegistry()
        {
            // TODO Register(TLSHashAlgorithm.None, () => new );
        }
    }
}