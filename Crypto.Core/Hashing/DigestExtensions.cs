using System.Buffers;

namespace Crypto.Core.Hashing
{
    public static class DigestExtensions
    {
        public static void Update(this IDigest digest, ReadOnlySequence<byte> sequence)
        {
            if (sequence.IsSingleSegment)
            {
                digest.Update(sequence.First.Span);
            }
            else
            {
                foreach (var segment in sequence)
                {
                    digest.Update(segment.Span);
                }
            }
        }
    }
}
