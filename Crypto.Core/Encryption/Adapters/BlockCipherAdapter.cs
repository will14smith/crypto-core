using System;
using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.Core.Encryption.Adapters
{
    public class BlockCipherAdapter : ICipher
    {
        public IBlockCipher BlockCipher { get; }

        public BlockCipherAdapter(IBlockCipher blockCipher)
        {
            BlockCipher = blockCipher;
        }

        public int KeySize => BlockCipher.KeySize;
        public int BlockLength => BlockCipher.BlockLength;

        public void Init(ICipherParameters parameters)
        {
            BlockCipher.Init(parameters);
        }

        public void Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertInputOutputBuffers(input, output);

            for (var i = 0; i < input.Length; i += BlockCipher.BlockLength)
            {
                BlockCipher.EncryptBlock(input.Slice(i, BlockLength), output.Slice(i, BlockLength));
            }
        }

        public void Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertInputOutputBuffers(input, output);

            for (var i = 0; i < input.Length; i += BlockCipher.BlockLength)
            {
                BlockCipher.DecryptBlock(input.Slice(i, BlockLength), output.Slice(i, BlockLength));
            }
        }
    }
}
