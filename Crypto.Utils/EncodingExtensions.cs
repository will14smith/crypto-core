using System;
using System.Buffers;
using System.Text;

namespace Crypto.Utils
{
    public static class EncodingExtensions
    {

        public static string GetString(this Encoding encoding, ReadOnlySequence<byte> input)
        {
            if (input.IsSingleSegment)
            {
                return encoding.GetString(input.First.Span);
            }

            return StringExtensions.Create((int)input.Length, input, (span, sequence) =>
            {
                foreach (var segment in sequence)
                {
                    encoding.GetChars(segment.Span, span);
                    span = span.Slice(segment.Length);
                }
            });

        }

        public static string GetString(this Encoding encoding, ReadOnlySpan<byte> input)
        {
            unsafe
            {
                fixed (byte* ptr = input)
                {
                    return encoding.GetString(ptr, input.Length);
                }
            }
        }

        public static int GetChars(this Encoding encoding, ReadOnlySpan<byte> input, Span<char> output)
        {
            if (input.IsEmpty) return 0;

            unsafe
            {
                fixed (byte* inputPtr = input)
                fixed (char* outputPtr = output)
                {
                    return encoding.GetChars(inputPtr, input.Length, outputPtr, output.Length);
                }
            }
        }
    }
}
