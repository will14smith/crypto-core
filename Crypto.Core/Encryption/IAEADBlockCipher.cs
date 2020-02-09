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

        AEADResult Encrypt(ReadOnlySpan<byte> input, Span<byte> output);
        AEADResult EncryptFinal(AEADResult previousResult);

        AEADResult Decrypt(ReadOnlySpan<byte> input, Span<byte> output);
        AEADResult DecryptFinal(AEADResult previousResult);
    }
    
    public ref struct AEADResult
    {
        public readonly ReadOnlySpan<byte> RemainingInput;
        public readonly Span<byte> RemainingOutput;

        public AEADResult(ReadOnlySpan<byte> remainingInput, Span<byte> remainingOutput)
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