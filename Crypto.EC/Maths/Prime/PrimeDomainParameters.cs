using System.Numerics;

namespace Crypto.EC.Maths.Prime
{
    public class PrimeDomainParameters : DomainParameters
    {
        public PrimeDomainParameters(BigInteger p, BigInteger a, BigInteger b, Point g, BigInteger n)
            : this(new PrimeField(p), a, b, g, n)
        {
        }
        public PrimeDomainParameters(IField field, BigInteger a, BigInteger b, Point g, BigInteger n)
            : base(field, new PrimeCurve(field, field.Value(a), field.Value(b)), g, n)
        {
        }
    }
}
