using System.Numerics;

namespace Crypto.ASN1
{
    public class ASN1Null : ASN1Object
    {
        public override BigInteger ByteLength => 0;

        public override void Accept(IASN1ObjectWriter writer)
        {
            writer.Write(this);
        }
    }
}
