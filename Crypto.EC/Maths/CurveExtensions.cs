using System.Linq;
using Crypto.Utils;

namespace Crypto.EC.Maths
{
    public static class CurveExtensions
    {
        public static Point<T> PointFromBinary<T>(this Curve<T> curve, byte[] b)
            where T : IFieldValue
        {
            SecurityAssert.NotNull(b);
            SecurityAssert.Assert(b.Length > 1 && b.Length % 2 == 1);

            var type = b[0];
            // only support uncompressed points for now
            SecurityAssert.Assert(type == 0x04);

            var len = (b.Length - 1) / 2;

            var x = curve.Field.Int(b.Skip(1).Take(len).ToBigInteger());
            var y = curve.Field.Int(b.Skip(1 + len).Take(len).ToBigInteger());

            var p = new Point<T>(x, y);
            SecurityAssert.Assert(curve.IsPointOnCurve(p));

            return p;
        }
    }
}
