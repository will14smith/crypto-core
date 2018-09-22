using System;
using Crypto.Core.Encryption.Parameters;

namespace Crypto.Core.Encryption
{
    public interface IAEADBlockCipher
    {
        int BlockLength { get; }
        int KeySize { get; }
        int TagLength { get; }

        void Init(ICipherParameters parameters);

        //TODO other functions...

        int Encrypt(ReadOnlySpan<byte> input, Span<byte> output);
        int EncryptFinal(Span<byte> output, Span<byte> tag);

        int Decrypt(ReadOnlySpan<byte> input, Span<byte> output);
        int DecryptFinal(ReadOnlySpan<byte> input, Span<byte> output);
    }
}