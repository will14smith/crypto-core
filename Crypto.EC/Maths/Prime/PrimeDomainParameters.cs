using System.Numerics;

namespace Crypto.EC.Maths.Prime
{
    public class PrimeDomainParameters
    {
        public PrimeField Field { get; }
        public Curve<PrimeValue> Curve { get; }

        public Point<PrimeValue> Generator { get; }
        public BigInteger Order { get; }

        public PrimeDomainParameters(BigInteger p, BigInteger a, BigInteger b, Point<PrimeValue> g, BigInteger n)
        {
            Field = new PrimeField(p);
            Curve = new Curve<PrimeValue>(Field, Field.Int(a), Field.Int(b));

            Generator = g;
            Order = n;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            var other = obj as PrimeDomainParameters;
            return other != null && Equals(other);
        }

        protected bool Equals(PrimeDomainParameters other)
        {
            return Equals(Field, other.Field) 
                   && Equals(Curve, other.Curve) 
                   && Equals(Generator, other.Generator) 
                   && Order.Equals(other.Order);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = Field != null ? Field.GetHashCode() : 0;
                hashCode = (hashCode * 397) ^ (Curve != null ? Curve.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (Generator != null ? Generator.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ Order.GetHashCode();
                return hashCode;
            }
        }
    }
}
