using System.Numerics;

namespace Crypto.EC.Maths.Char2
{
    public class Char2DomainParameters : DomainParameters<Char2Value>
    {
        public Char2DomainParameters(int m, int k, BigInteger a, BigInteger b, Point<Char2Value> g, BigInteger n)
            : base(new Char2Field(m, k), a, b, g, n)
        {
        }
        public Char2DomainParameters(int m, int k1, int k2, int k3, BigInteger a, BigInteger b, Point<Char2Value> g, BigInteger n)
            : base(new Char2Field(m, k1, k2, k3), a, b, g, n)
        {
        }
        public Char2DomainParameters(int m, int[] ks, BigInteger a, BigInteger b, Point<Char2Value> g, BigInteger n)
            : base(new Char2Field(m, ks), a, b, g, n)
        {
        }
    }
}
