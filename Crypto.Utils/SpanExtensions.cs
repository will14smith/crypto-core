using System;

namespace Crypto.Utils
{
    public static class SpanExtensions
    {
        public static Span<T> ToSpan<T>(this T[] array)
        {
            return new Span<T>(array);
        }
    }
}
