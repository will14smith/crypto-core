using System.Numerics;

namespace Crypto.EC.Maths
{
    public class DomainParameters
    {
        public IField Field { get; }
        public Curve Curve { get; }

        public Point Generator { get; }
        public BigInteger Order { get; }

        protected DomainParameters(IField field, Curve curve, Point g, BigInteger n)
        {
            Field = field;
            Curve = curve;

            Generator = g;
            Order = n;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            var other = obj as DomainParameters;
            return other != null && Equals(other);
        }

        protected bool Equals(DomainParameters other)
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