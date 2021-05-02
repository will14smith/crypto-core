using System;

namespace Crypto.TLS
{
    public struct TLSVersion : IEquatable<TLSVersion>
    {
        public static readonly TLSVersion TLS1_2 = new TLSVersion(3, 3);

        public byte Major { get; }
        public byte Minor { get; }

        public TLSVersion(byte major, byte minor)
        {
            Major = major;
            Minor = minor;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            return obj is TLSVersion && Equals((TLSVersion) obj);
        }

        public bool Equals(TLSVersion other)
        {
            return Major == other.Major && Minor == other.Minor;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return (Major.GetHashCode() * 397) ^ Minor.GetHashCode();
            }
        }

        public static bool operator ==(TLSVersion left, TLSVersion right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(TLSVersion left, TLSVersion right)
        {
            return !left.Equals(right);
        }

        public override string ToString()
        {
            return $"({Major}, {Minor})";
        }
    }
}
