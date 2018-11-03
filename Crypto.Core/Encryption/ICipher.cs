using System;
using Crypto.Core.Encryption.Parameters;

namespace Crypto.Core.Encryption
{
    public interface ICipher
    {
        int KeySize { get; }

        void Init(ICipherParameters parameters);

        CipherResult Encrypt(ReadOnlySpan<byte> input, Span<byte> output);
        CipherResult Decrypt(ReadOnlySpan<byte> input, Span<byte> output);
    }

    public ref struct CipherResult
    {
        public readonly ReadOnlySpan<byte> RemainingInput;
        public readonly Span<byte> RemainingOutput;

        public CipherResult(ReadOnlySpan<byte> remainingInput, Span<byte> remainingOutput)
        {
            RemainingInput = remainingInput;
            RemainingOutput = remainingOutput;
        }

        public void Deconstruct(out ReadOnlySpan<byte> input, out Span<byte> output)
        {
            input = RemainingInput;
            output = RemainingOutput;
        }
    }
}
