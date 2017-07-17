using System.Numerics;

namespace Crypto.EC.Maths.Prime
{
    public class PrimeDomainParameters : DomainParameters<PrimeValue>
    {
        public PrimeDomainParameters(BigInteger p, BigInteger a, BigInteger b, Point<PrimeValue> g, BigInteger n)
            : base(new PrimeField(p), a, b, g, n)
        {
        }
    }
}
