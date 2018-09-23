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
            if (obj is null) return false;
            return obj is TLSVersion version && Equals(version);
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

        public static bool operator <(TLSVersion left, TLSVersion right)
        {
            return left.Major < right.Major || !(left.Major > right.Major) && left.Minor < right.Minor;
        }

        public static bool operator >(TLSVersion left, TLSVersion right)
        {
            return left.Major > right.Major || !(left.Major < right.Major) && left.Minor > right.Minor;
        }
    }
}
