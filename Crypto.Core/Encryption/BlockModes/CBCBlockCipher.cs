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

        public override void EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.Assert(IVInitialised);
            SecurityAssert.AssertInputOutputBuffers(input, output, BlockLength);

            var tmp = new byte[BlockLength];
            input.Slice(0, BlockLength).CopyTo(tmp);

            BufferUtils.Xor(_workingIV, tmp);

            var target = output.Slice(0, BlockLength);
            Cipher.EncryptBlock(tmp, target);

            target.CopyTo(_workingIV);
        }

        public override void DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.Assert(IVInitialised);
            SecurityAssert.AssertInputOutputBuffers(input, output, BlockLength);

            Cipher.DecryptBlock(input.Slice(0, BlockLength), output.Slice(0, BlockLength));

            BufferUtils.Xor(_workingIV, output.Slice(0, BlockLength));

            input.Slice(0, BlockLength).CopyTo(_workingIV);
        }
    }
}
