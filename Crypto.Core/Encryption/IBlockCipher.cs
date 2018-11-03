using System;
using Crypto.Core.Encryption.Parameters;

namespace Crypto.Core.Encryption
{
    public interface IBlockCipher
    {
        int BlockLength { get; }
        int KeySize { get; }

        void Init(ICipherParameters parameters);

        BlockResult EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output);
        BlockResult DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output);
    }

    public ref struct BlockResult
    {
        public readonly ReadOnlySpan<byte> RemainingInput;
        public readonly Span<byte> RemainingOutput;

        public BlockResult(ReadOnlySpan<byte> remainingInput, Span<byte> remainingOutput)
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