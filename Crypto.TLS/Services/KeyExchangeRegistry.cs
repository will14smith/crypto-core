using Crypto.Core.Registry;
using Crypto.TLS.Identifiers;
using Crypto.TLS.KeyExchange;

namespace Crypto.TLS.Services
{
    public class KeyExchangeRegistry : BaseRegistry<TLSKeyExchange, IKeyExchange>
    {
        public KeyExchangeRegistry()
        {
            // TODO Register(TLSKeyExchange.Null, _ => );
        }
    }
}