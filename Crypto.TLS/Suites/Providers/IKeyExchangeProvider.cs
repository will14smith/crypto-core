using Crypto.TLS.Identifiers;
using Crypto.TLS.KeyExchanges;

namespace Crypto.TLS.Suites.Providers
{
    public interface IKeyExchangeProvider
    {
        IKeyExchange Create(TLSKeyExchange keyExchange);

        bool IsSupported(TLSKeyExchange keyExchange);
    }
}
