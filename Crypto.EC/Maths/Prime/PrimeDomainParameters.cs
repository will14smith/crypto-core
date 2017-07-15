using System.Numerics;

namespace Crypto.EC.Maths.Prime
{
    public class PrimeDomainParameters
    {
        public PrimeField Field { get; }
        public Curve<PrimeValue> Curve { get; }

        public Point<PrimeValue> Generator { get; set; }
        public BigInteger Order { get; set; }

        public PrimeDomainParameters(BigInteger p, BigInteger a, BigInteger b, Point<PrimeValue> g, BigInteger n)
        {
            Field = new PrimeField(p);
            Curve = new Curve<PrimeValue>(Field, Field.Int(a), Field.Int(b));

            Generator = g;
            Order = n;
        }
    }
}
