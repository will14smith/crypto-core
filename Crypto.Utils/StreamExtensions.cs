using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;

namespace Crypto.Utils
{
    public static class StreamExtensions
    {
        public static ReadOnlyMemory<byte> ReadExactly(this Stream stream, int requiredLength)
        {
            // :(
            var buffer = new byte[requiredLength];

            var offset = 0;
            while (requiredLength > 0)
            {
                var length = stream.Read(buffer, offset, buffer.Length - offset);
                requiredLength -= length;
            }

            return buffer.AsMemory();
        }

        public static ReadOnlySequence<byte> ReadAll(this Stream stream, int bufferSize = 1024)
        {
            var segments = new List<ReadOnlyMemory<byte>>();

            while (true)
            {
                var buffer = new byte[bufferSize];
                var length = stream.Read(buffer, 0, bufferSize);
                if (length == 0) break;

                segments.Add(buffer.AsMemory(0, length));
            }

            return segments.ToSequence();
        }

        public static Span<byte> Read(this Stream stream, Span<byte> output)
        {
            // :(
            var buffer = new byte[output.Length];
            var length = stream.Read(buffer, 0, buffer.Length);
            var useableOutput = output.Slice(0, length);
            buffer.CopyTo(useableOutput);
            return useableOutput;
        }

        public static void Write(this Stream stream, ReadOnlySequence<byte> input)
        {
            foreach (var segment in input)
            {
                stream.Write(segment.Span);
            }
        }
        public static void Write(this Stream stream, ReadOnlySpan<byte> input)
        {
            // :(
            var buffer = input.ToArray();

            stream.Write(buffer, 0, buffer.Length);
        }
    }
}
