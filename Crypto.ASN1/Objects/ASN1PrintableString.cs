using System.Numerics;

namespace Crypto.ASN1
{
    public class ASN1PrintableString : ASN1Object
    {
        public ASN1PrintableString(string value)
        {
            Value = value;
        }

        public string Value { get; }

        public override BigInteger ByteLength => Value.Length;
        public override void Accept(IASN1ObjectWriter writer)
        {
            writer.Write(this);
        }
    }
}