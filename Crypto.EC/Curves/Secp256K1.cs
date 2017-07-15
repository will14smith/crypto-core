using Crypto.EC.Maths;
using Crypto.EC.Maths.Prime;
using Crypto.Utils;

namespace Crypto.EC.Curves
{
    public class Secp256K1
    {
        public static PrimeDomainParameters Parameters;

        static Secp256K1()
        {
            var prime = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F".HexToBigInteger();
            var field = new PrimeField(prime);
            var curve = new Curve<PrimeValue>(field, field.Int(0), field.Int(7));

            // cofactor = 1

            Parameters = new PrimeDomainParameters(
                p: prime,
                a: curve.A.Value,
                b: curve.B.Value,
                g: curve.PointFromBinary(HexConverter.FromHex("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")),
                n: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".HexToBigInteger());
        }
    }
}
