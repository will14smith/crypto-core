using System;
using System.Numerics;

namespace Crypto.EC.Maths.Real
{
    public class RealValue : IFieldValue, IEquatable<RealValue>
    {
        public RealValue(decimal value)
        {
            Value = value;
        }

        public decimal Value { get; }

        public override bool Equals(object obj)
        {
            if (Object.ReferenceEquals(null, obj)) return false;
            if (Object.ReferenceEquals(this, obj)) return true;
            var other = obj as RealValue;
            return other != null && Equals(other);
        }

        public bool Equals(RealValue other)
        {
            if (Object.ReferenceEquals(null, other)) return false;
            if (Object.ReferenceEquals(this, other)) return true;

            return Value.Equals(other.Value);
        }

        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }

        public static bool operator ==(RealValue left, RealValue right)
        {
            return Object.Equals(left, right);
        }

        public static bool operator !=(RealValue left, RealValue right)
        {
            return !Object.Equals(left, right);
        }

        public BigInteger ToInt()
        {
            return new BigInteger(Value);
        }

        public override string ToString()
        {
            return Value.ToString();
        }
    }
}