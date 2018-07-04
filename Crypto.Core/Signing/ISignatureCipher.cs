using System;
using Crypto.Core.Encryption.Parameters;
using Crypto.Core.Hashing;

namespace Crypto.Core.Signing
{
    public interface ISignatureCipher
    {
        void Init(ICipherParameters parameters);

        ReadOnlySpan<byte> Sign(ReadOnlySpan<byte> input, IDigest hash);
        bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature, IDigest hash);
    }
}
