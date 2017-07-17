using System.Numerics;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.EC.Maths.Char2
{
    public class Char2Value : IFieldValue
    {
        public Char2Value(BigInteger value)
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
            var other = obj as Char2Value;
            return other != null && Equals(other);
        }

        public bool Equals(Char2Value other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return Value == other.Value;
        }

        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }

        public static bool operator ==(Char2Value left, Char2Value right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(Char2Value left, Char2Value right)
        {
            return !Equals(left, right);
        }

        public override string ToString()
        {
            return HexConverter.ToHex(Value.ToByteArray(Endianness.BigEndian));
        }
    }
}
