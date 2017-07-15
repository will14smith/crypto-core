using System;

namespace Crypto.TLS.Identifiers
{
    /// <summary>
    /// key exchanges aren't assigned numerical values.
    /// using GUIDs to identify them internally
    /// </summary>
    public struct TLSCipherAlgorithm
    {
        public static readonly TLSCipherAlgorithm Null = Guid.Empty;

        public TLSCipherAlgorithm(Guid id)
        {
            Id = id;
        }

        public Guid Id { get; }

        public override bool Equals(object obj)
        {
            if (!(obj is TLSCipherAlgorithm))
            {
                return false;
            }

            var other = (TLSCipherAlgorithm)obj;

            return Id == other.Id;
        }
        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

        public static implicit operator TLSCipherAlgorithm(Guid id)
        {
            return new TLSCipherAlgorithm(id);
        }
    }
}
