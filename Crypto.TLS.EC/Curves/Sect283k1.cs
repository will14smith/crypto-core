using Crypto.ASN1;
using Crypto.EC.Maths;
using Crypto.EC.Maths.Char2;
using Crypto.TLS.EC.Services;
using Crypto.Utils;

namespace Crypto.TLS.EC.Curves
{
    class Sect283K1
    {
        public static readonly NamedCurve Id = NamedCurve.sect283k1;
        public static readonly ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.132.0.16");
        public static readonly Char2DomainParameters Parameters;

        static Sect283K1()
        {
            var m = 283;
            var ks = new[] { 5, 7, 12 };

            var field = new Char2Field(m, ks);
            var curve = new Char2Curve(field, field.Value(0), field.Value(1));

            // cofactor = 1

            Parameters = new Char2DomainParameters(
                m: m,
                ks: ks,
                a: curve.A.Value,
                b: curve.B.Value,
                g: curve.PointFromBinary(HexConverter.FromHex("04" +
                                                              "0503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC2458492836" +
                                                              "01CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259")),
                n: "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61".HexToBigInteger());
        }
    }
}
