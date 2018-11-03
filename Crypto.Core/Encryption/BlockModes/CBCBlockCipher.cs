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
            SecurityAssert.Assert(IVInitialized);

            _workingIV = new byte[BlockLength];
            Array.Copy(IV, _workingIV, BlockLength);
        }

        public override BlockResult EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.Assert(IVInitialized);
            SecurityAssert.AssertInputOutputBuffers(input, output, BlockLength);

            var tmp = new byte[BlockLength];
            input.Slice(0, BlockLength).CopyTo(tmp);

            BufferUtils.Xor(_workingIV, tmp);

            var target = output.Slice(0, BlockLength);
            Cipher.EncryptBlock(tmp, target);

            target.CopyTo(_workingIV);

            return new BlockResult(input.Slice(BlockLength), output.Slice(BlockLength));
        }

        public override BlockResult DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.Assert(IVInitialized);
            SecurityAssert.AssertInputOutputBuffers(input, output, BlockLength);

            var inputBlock = input.Slice(0, BlockLength);
            var outputBlock = output.Slice(0, BlockLength);

            Cipher.DecryptBlock(inputBlock, outputBlock);
            BufferUtils.Xor(_workingIV, outputBlock);
            inputBlock.CopyTo(_workingIV);

            return new BlockResult(input.Slice(BlockLength), output.Slice(BlockLength));
        }
    }
}
