using System;
using Crypto.Utils;

namespace Crypto.Core.Encryption
{
    public static class BlockCipherSpanExtensions
    {
        public static BlockResult EncryptBlock(this IBlockCipher cipher, ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertBuffer(input, cipher.BlockLength);
            SecurityAssert.AssertBuffer(output, cipher.BlockLength);
            
            var inputBuffer = input.Slice(0, cipher.BlockLength).ToArray();
            var outputBuffer = new byte[cipher.BlockLength];
            
            cipher.EncryptBlock(inputBuffer, 0, outputBuffer, 0);

            outputBuffer.CopyTo(output);
            
            return new BlockResult(input.Slice(cipher.BlockLength), output.Slice(cipher.BlockLength));
        }

        public static BlockResult DecryptBlock(this IBlockCipher cipher, ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertBuffer(input, cipher.BlockLength);
            SecurityAssert.AssertBuffer(output, cipher.BlockLength);
            
            var inputBuffer = input.Slice(0, cipher.BlockLength).ToArray();
            var outputBuffer = new byte[cipher.BlockLength];
            
            cipher.DecryptBlock(inputBuffer, 0, outputBuffer, 0);

            outputBuffer.CopyTo(output);
            
            return new BlockResult(input.Slice(cipher.BlockLength), output.Slice(cipher.BlockLength));
        }
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