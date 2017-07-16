using Crypto.EC.Maths.Prime;
using Crypto.TLS.EC.KeyExchanges;

namespace Crypto.TLS.EC.Config
{
    public class ECDHExchangeConfig
    {
        public ECParameters ServerParameters { get; set; }
        // TODO make configurable
        public PrimeDomainParameters Parameters { get; set; }

        // TODO make configurable
        public PrimeValue D { get; set; }
    }
}
