namespace Crypto.EC.Maths.Prime
{
    public class PrimeCurve : Curve
    {
        public PrimeCurve(IField field, FieldValue a, FieldValue b) : base(field, a, b)
        {
        }

        public override bool IsPointOnCurve(Point point)
        {
            var x = point.X;
            var y = point.Y;

            var lhs = Field.Multiply(y, y);
            var rhs = Field.Add(Field.Add(Field.Multiply(Field.Multiply(x, x), x), Field.Multiply(A, x)), B);

            return Equals(lhs, rhs);
        }
    }
}
