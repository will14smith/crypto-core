namespace Crypto.TLS.Identifiers
{
    public struct TLSSignatureAlgorithm
    {
        public static readonly TLSSignatureAlgorithm Anonymous = 0;

        public TLSSignatureAlgorithm(byte id)
        {
            Id = id;
        }

        public byte Id { get; }

        public override bool Equals(object obj)
        {
            var other = obj as TLSSignatureAlgorithm?;

            return Id == other?.Id;
        }

        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

        public static implicit operator TLSSignatureAlgorithm(byte id)
        {
            return new TLSSignatureAlgorithm(id);
        }
    }
}