using System;
using Crypto.Utils;

namespace Crypto.Core.Encryption.BlockModes
{
    public class CBCBlockCipher : IVBlockCipher
    {
        private byte[] _workingIV;

        public CBCBlockCipher(IBlockCipher cipher) : base(cipher)
        {
        }

        protected override void Reset()
        {
            SecurityAssert.Assert(IVInitialised);

            _workingIV = new byte[BlockLength];
            Array.Copy(IV, _workingIV, BlockLength);
        }

        public override void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            SecurityAssert.Assert(IVInitialised);
            SecurityAssert.AssertBuffer(input, inputOffset, BlockLength);
            SecurityAssert.AssertBuffer(output, outputOffset, BlockLength);

            var tmp = new byte[BlockLength];
            Array.Copy(input, inputOffset, tmp, 0, BlockLength);

            BufferUtils.Xor(_workingIV, 0, tmp, 0, BlockLength);

            Cipher.EncryptBlock(tmp, 0, output, outputOffset);

            Array.Copy(output, outputOffset, _workingIV, 0, BlockLength);
        }

        public override void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            SecurityAssert.Assert(IVInitialised);
            SecurityAssert.AssertBuffer(input, inputOffset, BlockLength);
            SecurityAssert.AssertBuffer(output, outputOffset, BlockLength);

            Cipher.DecryptBlock(input, inputOffset, output, outputOffset);

            BufferUtils.Xor(_workingIV, 0, output, outputOffset, BlockLength);
            Array.Copy(input, inputOffset, _workingIV, 0, BlockLength);
        }
    }
}
