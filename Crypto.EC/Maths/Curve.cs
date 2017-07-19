using System;

namespace Crypto.EC.Maths
{
    public abstract class Curve
    { 
        public IField Field { get; }

        public FieldValue A { get; }
        public FieldValue B { get; }

        protected Curve(IField field, FieldValue a, FieldValue b)
        {
            Field = field;

            A = a;
            B = b;
        }

        public override string ToString()
        {
            return $"y^2 = x^3 + {A}x + {B}";
        }

        public abstract bool IsPointOnCurve(Point point);

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((Curve) obj);
        }

        protected bool Equals(Curve other)
        {
            return Equals(Field, other.Field) && Equals(A, other.A) && Equals(B, other.B);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = (Field != null ? Field.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (A != null ? A.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (B != null ? B.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}
