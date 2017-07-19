using System.Numerics;

namespace Crypto.EC.Maths.Real
{
    public class RealField : IField
    {
        public FieldValue Value(BigInteger i)
        {
            return new FieldValue(i);
        }

        public FieldValue Negate(FieldValue a)
        {
            return Value(-a.Value);
        }

        public FieldValue Add(FieldValue a, FieldValue b)
        {
            return Value(a.Value + b.Value);
        }

        public FieldValue Sub(FieldValue a, FieldValue b)
        {
            return Value(a.Value - b.Value);
        }

        public FieldValue Multiply(FieldValue a, FieldValue b)
        {
            return Value(a.Value * b.Value);
        }

        public FieldValue Divide(FieldValue a, FieldValue b)
        {
            return Value(a.Value / b.Value);
        }
    }
}