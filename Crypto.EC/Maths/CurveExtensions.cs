using System.Linq;
using Crypto.Utils;

namespace Crypto.EC.Maths
{
    public static class CurveExtensions
    {
        public static Point PointFromBinary(this Curve curve, byte[] b)
        {
            SecurityAssert.NotNull(b);
            SecurityAssert.Assert(b.Length > 1 && b.Length % 2 == 1);

            var type = b[0];
            // only support uncompressed points for now
            SecurityAssert.Assert(type == 0x04);

            var len = (b.Length - 1) / 2;

            var x = curve.Field.Value(b.Skip(1).Take(len).ToBigInteger());
            var y = curve.Field.Value(b.Skip(1 + len).Take(len).ToBigInteger());

            var p = new Point(x, y);
            SecurityAssert.Assert(curve.IsPointOnCurve(p));

            return p;
        }
    }
}
