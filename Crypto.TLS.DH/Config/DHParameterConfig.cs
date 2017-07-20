using System.Numerics;

namespace Crypto.TLS.DH.Config
{
    public class DHParameterConfig
    {
        internal DHParameterConfig()
        {
        }
        public DHParameterConfig(BigInteger p, BigInteger g)
        {
            P = p;
            G = g;
        }

        public BigInteger P { get; internal set; }
        public BigInteger G { get; internal set; }
    }
}
