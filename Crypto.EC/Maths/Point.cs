using System;
using System.Collections.Generic;
using System.Linq;
using Crypto.Utils.IO;
using Crypto.Utils;

namespace Crypto.EC.Maths
{
    public class Point<TFieldValue>
        where TFieldValue : IFieldValue
    {
        public TFieldValue X { get; }
        public TFieldValue Y { get; }

        public Point(TFieldValue x, TFieldValue y)
        {
            X = x;
            Y = y;
        }

        // TODO type
        public byte[] ToBytes()
        {
            var x = X.ToInt().ToByteArray(Endianness.BigEndian);
            var y = Y.ToInt().ToByteArray(Endianness.BigEndian);

            SecurityAssert.Assert(x.Length == y.Length);

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
            var other = obj as Point<TFieldValue>;
            return other != null && Equals(other);
        }

        protected bool Equals(Point<TFieldValue> other)
        {
            return EqualityComparer<TFieldValue>.Default.Equals(X, other.X)
                && EqualityComparer<TFieldValue>.Default.Equals(Y, other.Y);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return (EqualityComparer<TFieldValue>.Default.GetHashCode(X) * 397) ^ EqualityComparer<TFieldValue>.Default.GetHashCode(Y);
            }
        }

        public static Point<TFieldValue> Add(Curve<TFieldValue> curve, Point<TFieldValue> a, Point<TFieldValue> b)
        {
            if (a == null) { return b; }
            if (b == null) { return a; }

            var field = curve.Field;

            TFieldValue m;

            if (Equals(a, b))
            {
                var mt = field.Add(field.Multiply(field.Int(3), field.Multiply(a.X, a.X)), curve.A);
                var mb = field.Multiply(field.Int(2), a.Y);
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

            return new Point<TFieldValue>(x, field.Negate(y));
        }

        public static Point<TFieldValue> Multiply(Curve<TFieldValue> curve, TFieldValue a, Point<TFieldValue> b)
        {
            var i = a.ToInt();

            if (i < 0)
            {
                throw new NotImplementedException();
            }

            Point<TFieldValue> result = null;

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