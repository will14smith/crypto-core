using System.Collections.Generic;

namespace Crypto.EC.Maths
{
    public class Curve<TFieldValue>
        where TFieldValue : IFieldValue
    {
        public IField<TFieldValue> Field { get; }

        public TFieldValue A { get; }
        public TFieldValue B { get; }

        public Curve(IField<TFieldValue> field, TFieldValue a, TFieldValue b)
        {
            Field = field;

            A = a;
            B = b;
        }

        public override string ToString()
        {
            return $"y^2 = x^3 + {A}x + {B}";
        }

        public bool IsPointOnCurve(Point<TFieldValue> point)
        {
            var x = point.X;
            var y = point.Y;

            var lhs = Field.Multiply(y, y);
            var rhs = Field.Add(Field.Add(Field.Multiply(Field.Multiply(x, x), x), Field.Multiply(A, x)), B);

            return Equals(lhs, rhs);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            var other = obj as Curve<TFieldValue>;
            return other != null && Equals(other);
        }

        protected bool Equals(Curve<TFieldValue> other)
        {
            return Equals(Field, other.Field) 
                && EqualityComparer<TFieldValue>.Default.Equals(A, other.A) 
                && EqualityComparer<TFieldValue>.Default.Equals(B, other.B);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = Field != null ? Field.GetHashCode() : 0;
                hashCode = (hashCode * 397) ^ EqualityComparer<TFieldValue>.Default.GetHashCode(A);
                hashCode = (hashCode * 397) ^ EqualityComparer<TFieldValue>.Default.GetHashCode(B);
                return hashCode;
            }
        }
    }
}
