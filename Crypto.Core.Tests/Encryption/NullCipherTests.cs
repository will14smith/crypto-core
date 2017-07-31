using System;
using System.Linq;
using Crypto.Core.Encryption;
using Xunit;

namespace Crypto.Core.Tests.Encryption
{
    public class NullCipherTests
    {
        [Fact]
        public void Encrypt_ShouldCopyIntact()
        {
            var input = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 };
            var output = new byte[input.Length];

            new NullCipher().Encrypt(input, 0, output, 0, input.Length);

            Assert.Equal(input, output);
        }
        [Fact]
        public void Encrypt_WithOffset_ShouldCopyIntact()
        {
            var input = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 };
            var output = new byte[6];

            new NullCipher().Encrypt(input, 2, output, 4, 2);

            Assert.Equal(input.Skip(2).Take(2), output.Skip(4).Take(2));
            Assert.Equal(new byte[] { 0, 0, 0, 0 }, output.Take(4));
        }
        
        [Fact]
        public void Decrypt_ShouldCopyIntact()
        {
            var input = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 };
            var output = new byte[input.Length];

            new NullCipher().Decrypt(input, 0, output, 0, input.Length);

            Assert.Equal(input, output);
        }
        [Fact]
        public void Decrypt_WithOffset_ShouldCopyIntact()
        {
            var input = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 };
            var output = new byte[6];

            new NullCipher().Decrypt(input, 2, output, 4, 2);

            Assert.Equal(input.Skip(2).Take(2), output.Skip(4).Take(2));
            Assert.Equal(new byte[] { 0, 0, 0, 0 }, output.Take(4));
        }
    }
}
