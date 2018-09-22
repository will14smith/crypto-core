using System;

namespace Crypto.Utils
{
    public static class SpanExtensions
    {
        public static Span<T> ToSpan<T>(this T[] array)
        {
            return new Span<T>(array);
        }

        public static bool EqualConstantTime(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            var result = 0;
            for (var i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

    }
}
