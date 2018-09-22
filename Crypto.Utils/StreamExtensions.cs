using System;
using System.IO;

namespace Crypto.Utils
{
    public static class StreamExtensions
    {
        public static void Write(this Stream stream, ReadOnlySpan<byte> input)
        {
            // :(
            var buffer = input.ToArray();

            stream.Write(buffer, 0, buffer.Length);
        }
    }
}
