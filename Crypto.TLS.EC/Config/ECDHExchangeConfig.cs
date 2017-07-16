using Crypto.EC.Maths.Prime;

namespace Crypto.TLS.EC.Config
{
    public class ECDHExchangeConfig
    {
        // TODO make configurable
        public PrimeDomainParameters Parameters { get; set; }
        public PrimeValue D { get; set; }
    }
}
