using Crypto.Core.Registry;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.Suites.Registries
{
    public class PRFHashRegistry : BaseRegistry<TLSHashAlgorithm, TLSHashAlgorithm>
    {
        public PRFHashRegistry()
        {
        }
    }
}
