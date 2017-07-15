using Crypto.Core.Registry;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.Services
{
    public class PRFHashRegistry : BaseRegistry<TLSHashAlgorithm, TLSHashAlgorithm>
    {
        public PRFHashRegistry()
        {
        }
    }
}
