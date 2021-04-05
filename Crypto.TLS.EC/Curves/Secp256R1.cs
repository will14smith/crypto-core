using Crypto.ASN1;
using Crypto.EC.Maths;
using Crypto.EC.Maths.Prime;
using Crypto.TLS.EC.Services;
using Crypto.Utils;

namespace Crypto.TLS.EC.Curves
{
    public class Secp256R1
    {
        public static readonly NamedCurve Id = NamedCurve.secp256r1;
        public static readonly ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.2.840.10045.3.1.7");
        public static readonly PrimeDomainParameters Parameters;

        static Secp256R1()
        {
            var prime = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF".HexToBigInteger();
            var field = new PrimeField(prime);

            var a = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC".HexToBigInteger();
            var b = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B".HexToBigInteger();
            var curve = new PrimeCurve(field, field.Value(a), field.Value(b));
            
            Parameters = new PrimeDomainParameters(
                p: prime,
                a: curve.A.Value,
                b: curve.B.Value,
                g: curve.PointFromBinary(HexConverter.FromHex("046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")),
                n: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551".HexToBigInteger());
        }
    }
}
