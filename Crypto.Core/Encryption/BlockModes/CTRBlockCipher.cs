using System;
using Crypto.Utils;

namespace Crypto.Core.Encryption.BlockModes
{
    public class CTRBlockCipher : IVBlockCipher
    {
        private byte[] _counter;

        public CTRBlockCipher(IBlockCipher cipher) : base(cipher)
        {
            _counter = new byte[BlockLength];
        }

        protected override void Reset()
        {
            SecurityAssert.Assert(IVInitialised);

            _counter = new byte[BlockLength];
            Array.Copy(IV, 0, _counter, 0, BlockLength);
        }

        public override void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            ProcessBlock(input, inputOffset, output, outputOffset);
        }

        public override void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            ProcessBlock(input, inputOffset, output, outputOffset);
        }

        private void ProcessBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            SecurityAssert.AssertBuffer(input, inputOffset, BlockLength);
            SecurityAssert.AssertBuffer(output, outputOffset, BlockLength);

            var counterOutput = new byte[BlockLength];
            Cipher.EncryptBlock(_counter, 0, counterOutput, 0);

            // XOR input
            for (var i = 0; i < BlockLength; i++)
            {
                output[outputOffset + i] = (byte)(counterOutput[i] ^ input[inputOffset + i]);
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
