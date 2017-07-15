using System;
using System.Numerics;

namespace Crypto.EC.Maths.Prime
{
    public class PrimeValue : IFieldValue, IEquatable<PrimeValue>
    {
        public PrimeValue(BigInteger value)
        {
            Value = value;
        }

        public BigInteger Value { get; }

        public BigInteger ToInt()
        {
            return Value;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            var other = obj as PrimeValue;
            return other != null && Equals(other);
        }

        public bool Equals(PrimeValue other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return Value.Equals(other.Value);
        }

        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }

        public static bool operator ==(PrimeValue left, PrimeValue right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(PrimeValue left, PrimeValue right)
        {
            return !Equals(left, right);
        }

        public override string ToString()
        {
            return Value.ToString();
        }
    }
}