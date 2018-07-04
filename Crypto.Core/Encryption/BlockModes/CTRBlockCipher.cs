using System;
using Crypto.Utils;

namespace Crypto.Core.Encryption.BlockModes
{
    public class CTRBlockCipher : IVBlockCipher
    {
        private byte[] _counter;

        public CTRBlockCipher(IBlockCipher cipher) : base(cipher)
        {
        }

        protected override void Reset()
        {
            SecurityAssert.Assert(IVInitialised);

            _counter = new byte[BlockLength];
            Array.Copy(IV, 0, _counter, 0, BlockLength);
        }

        public override void EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            ProcessBlock(input, output);
        }

        public override void DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            ProcessBlock(input, output);
        }

        private void ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertInputOutputBuffers(input, output, BlockLength);

            var counterOutput = new byte[BlockLength];
            Cipher.EncryptBlock(_counter, counterOutput);

            // XOR input
            for (var i = 0; i < BlockLength; i++)
            {
                output[i] = (byte)(counterOutput[i] ^ input[i]);
            }

            // increment counter
            Inc();
        }

        public void Inc()
        {
            var j = BlockLength;
            while (j > 0 && ++_counter[--j] == 0)
            {
            }
        }
    }
}
