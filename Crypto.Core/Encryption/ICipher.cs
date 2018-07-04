using System;
using Crypto.Core.Encryption.Parameters;

namespace Crypto.Core.Encryption
{
    public interface ICipher
    {
        int KeySize { get; }

        void Init(ICipherParameters parameters);

        void Encrypt(ReadOnlySpan<byte> input, Span<byte> output);
        void Decrypt(ReadOnlySpan<byte> input, Span<byte> output);
    }
}
