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

        public CipherResult Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertInputOutputBuffers(input, output);

            while (input.Length >= BlockCipher.BlockLength)
            {
                (input, output) = BlockCipher.EncryptBlock(input, output);
            }

            return new CipherResult(input, output);
        }

        public CipherResult Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertInputOutputBuffers(input, output);

            while (input.Length >= BlockCipher.BlockLength)
            {
                (input, output) = BlockCipher.DecryptBlock(input, output);
            }

            return new CipherResult(input, output);
        }
    }
}
