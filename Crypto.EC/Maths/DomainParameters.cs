using System;
using System.Numerics;

namespace Crypto.EC.Maths
{
    public abstract class DomainParameters<TFieldValue> 
        where TFieldValue : IFieldValue
    {
        public IField<TFieldValue> Field { get; }
        public Curve<TFieldValue> Curve { get; }

        public Point<TFieldValue> Generator { get; }
        public BigInteger Order { get; }

        protected DomainParameters(IField<TFieldValue> field, BigInteger a, BigInteger b, Point<TFieldValue> g, BigInteger n)
        {
            Field = field;
            Curve = new Curve<TFieldValue>(Field, Field.Int(a), Field.Int(b));

            Generator = g;
            Order = n;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (object.ReferenceEquals(this, obj)) return true;
            var other = obj as DomainParameters<TFieldValue>;
            return other != null && Equals(other);
        }

        protected bool Equals(DomainParameters<TFieldValue> other)
        {
            return Object.Equals(Field, other.Field)
                   && Object.Equals(Curve, other.Curve)
                   && Object.Equals(Generator, other.Generator)
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