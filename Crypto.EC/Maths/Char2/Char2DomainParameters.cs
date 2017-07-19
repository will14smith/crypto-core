using System.Numerics;

namespace Crypto.EC.Maths.Char2
{
    public class Char2DomainParameters : DomainParameters
    {
        public Char2DomainParameters(int m, int k, BigInteger a, BigInteger b, Point g, BigInteger n)
            : this(m, new[] { k }, a, b, g, n)
        {
        }
        public Char2DomainParameters(int m, int k1, int k2, int k3, BigInteger a, BigInteger b, Point g, BigInteger n)
            : this(m, new[] { k1, k2, k3 }, a, b, g, n)
        {
        }
        public Char2DomainParameters(int m, int[] ks, BigInteger a, BigInteger b, Point g, BigInteger n)
            : this(new Char2Field(m, ks), a, b, g, n)
        {
        }

        public Char2DomainParameters(IField field, BigInteger a, BigInteger b, Point g, BigInteger n)
            : base(field, new Char2Curve(field, field.Value(a), field.Value(b)), g, n)
        {
        }
    }
}
