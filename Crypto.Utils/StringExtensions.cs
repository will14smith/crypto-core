using System;

namespace Crypto.Utils
{
    public static class StringExtensions
    {
        public delegate void SpanAction<T, in TArg>(Span<T> span, TArg arg);

        public static unsafe string Create<TState>(int length, TState state, SpanAction<char, TState> action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));

            if (length <= 0)
            {
                if (length == 0)
                    return string.Empty;
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            var result = new string('\0', length);
            fixed (char* r = result)
            {
                action(new Span<char>(r, length), state);
            }
            return result;
        }
    }
}
