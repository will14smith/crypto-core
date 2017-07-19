using System;
using System.Linq;
using Crypto.Utils.IO;
using Crypto.Utils;

namespace Crypto.EC.Maths
{
    public class Point : IEquatable<Point>
    {
        public FieldValue X { get; }
        public FieldValue Y { get; }

        public Point(FieldValue x, FieldValue y)
        {
            X = x;
            Y = y;
        }

        // TODO different types
        public byte[] ToBytes()
        {
            var x = X.Value.ToByteArray(Endianness.BigEndian);
            var y = Y.Value.ToByteArray(Endianness.BigEndian);

            if (x.Length != y.Length)
            {
                throw new NotImplementedException("Padding");
            }

            return new[]
            {
                // Type
                (byte) 0x4
            }.Concat(x).Concat(y).ToArray();
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            var other = obj as Point;
            return other != null && Equals(other);
        }

        public bool Equals(Point other)
        {
            return Equals(X, other.X)
                && Equals(Y, other.Y);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return (X.GetHashCode() * 397) ^ Y.GetHashCode();
            }
        }

        public static Point Add(Curve curve, Point a, Point b)
        {
            if (a == null) { return b; }
            if (b == null) { return a; }

            var field = curve.Field;

            FieldValue m;

            if (Equals(a, b))
            {
                var mt = field.Add(field.Multiply(field.Value(3), field.Multiply(a.X, a.X)), curve.A);
                var mb = field.Multiply(field.Value(2), a.Y);
                m = field.Divide(mt, mb);
            }
            else
            {
                var mt = field.Sub(a.Y, b.Y);
                var mb = field.Sub(a.X, b.X);
                m = field.Divide(mt, mb);
            }

            var x = field.Sub(field.Sub(field.Multiply(m, m), a.X), b.X);
            var y = field.Add(b.Y, field.Multiply(m, field.Sub(x, b.X)));

            return new Point(x, field.Negate(y));
        }

        public static Point Multiply(Curve curve, FieldValue a, Point b)
        {
            var i = a.Value;

            if (i < 0)
            {
                throw new NotImplementedException();
            }

            Point result = null;

            while (i > 0)
            {
                if ((i & 1) == 1)
                {
                    result = Add(curve, result, b);
                }

                b = Add(curve, b, b);

                i >>= 1;
            }

            return result;
        }
    }
}