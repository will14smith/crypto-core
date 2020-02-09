using System;
using System.Numerics;

namespace Crypto.EC.Maths
{
    public class FieldValue : IEquatable<FieldValue>
    {
        public FieldValue(BigInteger value)
        {
            Value = value;
        }

        public BigInteger Value { get; }
        
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj is FieldValue other && Equals(other);
        }

        public bool Equals(FieldValue other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return Value.Equals(other.Value);
        }

        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }

        public static bool operator ==(FieldValue left, FieldValue right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(FieldValue left, FieldValue right)
        {
            return !Equals(left, right);
        }

        public override string ToString()
        {
            return Value.ToString();
        }
    }
}