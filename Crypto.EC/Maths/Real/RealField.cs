using System;
using System.Numerics;

namespace Crypto.EC.Maths.Real
{
    public class RealField : IField<RealValue>
    {
        public RealValue Int(BigInteger i)
        {
            return new RealValue((decimal)i);
        }

        public RealValue Negate(RealValue a)
        {
            return new RealValue(-a.Value);
        }

        public RealValue Add(RealValue a, RealValue b)
        {
            return new RealValue(a.Value + b.Value);
        }

        public RealValue Sub(RealValue a, RealValue b)
        {
            return new RealValue(a.Value - b.Value);
        }

        public RealValue Multiply(RealValue a, RealValue b)
        {
            return new RealValue(a.Value * b.Value);
        }

        public RealValue Divide(RealValue a, RealValue b)
        {
            return new RealValue(a.Value / b.Value);
        }

        public RealValue Sqrt(RealValue a)
        {
            return new RealValue((decimal)Math.Sqrt((double)a.Value));
        }
    }
}