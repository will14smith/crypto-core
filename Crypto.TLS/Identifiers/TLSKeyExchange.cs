using System;

namespace Crypto.TLS.Identifiers
{
    /// <summary>
    /// key exchanges aren't assigned numerical values.
    /// using GUIDs to identify them internally
    /// </summary>
    public struct TLSKeyExchange
    {
        public static readonly TLSKeyExchange Null = Guid.Empty;

        public TLSKeyExchange(Guid id)
        {
            Id = id;
        }

        public Guid Id { get; }

        public override bool Equals(object obj)
        {
            if (!(obj is TLSKeyExchange))
            {
                return false;
            }

            var other = (TLSKeyExchange)obj;

            return Id == other.Id;
        }
        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

        public static implicit operator TLSKeyExchange(Guid id)
        {
            return new TLSKeyExchange(id);
        }
    }
}
