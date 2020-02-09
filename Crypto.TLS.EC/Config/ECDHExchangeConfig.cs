using Crypto.EC.Maths;

namespace Crypto.TLS.EC.Config
{
    public class ECDHExchangeConfig
    {
        public DomainParameters? Parameters { get; set; }
        public FieldValue? D { get; set; }
    }
}
