using System;

namespace Crypto.Utils
{
    public static class MemoryExtensions
    {
        public static (Memory<T> Pre, Memory<T> Post) Split<T>(this Memory<T> memory, int offset)
        {
            var pre = memory.Slice(0, offset);
            var post = memory.Slice(offset);

            return (pre, post);
        }

        public static (Memory<T> Pre, Memory<T> Content, Memory<T> Post) Split<T>(this Memory<T> span, int offset, int length)
        {
            var pre = span.Slice(0, offset);
            var content = span.Slice(offset, length);
            var post = span.Slice(offset + length);

            return (pre, content, post);
        }

        public static (ReadOnlyMemory<T>, ReadOnlyMemory<T>) Split<T>(this ReadOnlyMemory<T> memory, int offset)
        {
            var pre = memory.Slice(0, offset);
            var post = memory.Slice(offset);

            return (pre, post);
        }

        public static (ReadOnlyMemory<T> Pre, ReadOnlyMemory<T> Content, ReadOnlyMemory<T> Post) Split<T>(this ReadOnlyMemory<T> span, int offset, int length)
        {
            var pre = span.Slice(0, offset);
            var content = span.Slice(offset, length);
            var post = span.Slice(offset + length);

            return (pre, content, post);
        }
    }
}
