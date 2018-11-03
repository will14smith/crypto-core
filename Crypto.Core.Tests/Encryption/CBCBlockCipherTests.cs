using System;
using Crypto.Core.Encryption;
using Crypto.Core.Encryption.Adapters;
using Crypto.Core.Encryption.BlockModes;
using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;
using Xunit;

namespace Crypto.Core.Tests.Encryption
{
    public class CBCBlockCipherTests
    {
        [Fact]
        public void CanEncryptDecrypt()
        {
            var iv = new byte[] { 1, 2, 3, 4 };
            var x = new BlockCipherAdapter(new CBCBlockCipher(new MockBlockCipher()));

            var input = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var encrypted = new byte[8];
            var output = new byte[8];

            x.Init(new IVParameter(null, iv));
            x.Encrypt(input, encrypted);
            x.Init(new IVParameter(null, iv));
            x.Decrypt(encrypted, output);

            Assert.Equal(HexConverter.ToHex(input), HexConverter.ToHex(output));
        }
    }

    public class MockBlockCipher : IBlockCipher
    {
        public int BlockLength => 4;
        public int KeySize => 4;

        public void Init(ICipherParameters parameters)
        {
        }

        public BlockResult EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            input.CopyTo(output);

            return new BlockResult(Span<byte>.Empty, output.Slice(input.Length));
        }

        public BlockResult DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            input.CopyTo(output);

            return new BlockResult(Span<byte>.Empty, output.Slice(input.Length));
        }
    }
}
