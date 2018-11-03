using System;
using Crypto.Core.Encryption.Parameters;

namespace Crypto.Core.Encryption.BlockModes
{
    // ECB is just a NOP block mode
    public class ECBBlockCipher : IBlockCipher
    {
        public IBlockCipher Cipher { get; }

        public ECBBlockCipher(IBlockCipher cipher)
        {
            Cipher = cipher;
        }

        public int BlockLength => Cipher.BlockLength;
        public int KeySize => Cipher.KeySize;

        public void Init(ICipherParameters parameters)
        {
            Cipher.Init(parameters);
        }

        public BlockResult EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output) => Cipher.EncryptBlock(input, output);

        public BlockResult DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output) => Cipher.DecryptBlock(input, output);
    }
}
