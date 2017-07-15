using System.Numerics;

namespace Crypto.TLS.DH.Config
{
    public class DHParameterConfig
    {
        public DHParameterConfig(BigInteger p, BigInteger g)
        {
            P = p;
            G = g;
        }

        public BigInteger P { get; }
        public BigInteger G { get; }
    }
}
