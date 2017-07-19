namespace Crypto.EC.Maths.Char2
{
    public class Char2Curve : Curve
    {
        public Char2Curve(IField field, FieldValue a, FieldValue b) : base(field, a, b)
        {
        }

        public override bool IsPointOnCurve(Point point)
        {
            var x = point.X;
            var y = point.Y;

            var lhs = Field.Add(Field.Multiply(y, y), Field.Multiply(x, y));
            var rhs = Field.Add(Field.Add(Field.Multiply(Field.Multiply(x, x), x), Field.Multiply(A, x)), B);

            return Equals(lhs, rhs);
        }
    }
}
