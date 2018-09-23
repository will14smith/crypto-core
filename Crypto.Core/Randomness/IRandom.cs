using System;

namespace Crypto.Core.Randomness
{
    public interface IRandom
    {
        int RandomInt(int min, int max);
        ReadOnlySpan<byte> RandomBytes(int length);
        void RandomBytes(Span<byte> target);
    }
}
