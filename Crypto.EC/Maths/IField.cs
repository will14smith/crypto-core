using System.Numerics;

namespace Crypto.EC.Maths
{
    public interface IField
    {
        FieldValue Value(BigInteger i);

        FieldValue Negate(FieldValue a);

        FieldValue Add(FieldValue a, FieldValue b);
        FieldValue Sub(FieldValue a, FieldValue b);
        FieldValue Multiply(FieldValue a, FieldValue b);
        FieldValue Divide(FieldValue a, FieldValue b);
    }
}