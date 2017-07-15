namespace Crypto.TLS.Identifiers
{
    public struct TLSHashAlgorithm
    {
        public static readonly TLSHashAlgorithm None = 0;

        public TLSHashAlgorithm(byte id)
        {
            Id = id;
        }

        public byte Id { get; }

        public override bool Equals(object obj)
        {
            var other = obj as TLSHashAlgorithm?;

            return Id == other?.Id;
        }

        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

        public static implicit operator TLSHashAlgorithm(byte id)
        {
            return new TLSHashAlgorithm(id);
        }
    }
}
