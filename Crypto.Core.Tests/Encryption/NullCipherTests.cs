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

            new NullCipher().Encrypt(input, output);

            Assert.Equal(input, output);
        }
        
        [Fact]
        public void Decrypt_ShouldCopyIntact()
        {
            var input = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 };
            var output = new byte[input.Length];

            new NullCipher().Decrypt(input, output);

            Assert.Equal(input, output);
        }
    }
}
