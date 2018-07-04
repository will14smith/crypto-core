using System;
using Crypto.Core.Encryption.Parameters;

namespace Crypto.Core.Encryption
{
    public interface IBlockCipher
    {
        int BlockLength { get; }
        int KeySize { get; }

        void Init(ICipherParameters parameters);

        void EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output);
        void DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output);
    }
}