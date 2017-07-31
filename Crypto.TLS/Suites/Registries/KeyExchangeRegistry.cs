using Crypto.Core.Registry;
using Crypto.TLS.Identifiers;
using Crypto.TLS.KeyExchanges;

namespace Crypto.TLS.Suites.Registries
{
    public class KeyExchangeRegistry : BaseServiceRegistry<TLSKeyExchange, IKeyExchange>
    {
        public KeyExchangeRegistry()
        {
            // TODO Register(TLSKeyExchange.Null, () => );
        }
    }
}