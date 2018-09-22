using Crypto.Utils;
using Xunit;

namespace Crypto.RC4.Tests
{
    public class RC4CipherTests
    {
        [Fact]
        public void RC4_128_Encrypt_ShouldWork()
        {
            var input = new byte[16];
            var output = new byte[16];

            var key = HexConverter.FromHex("ebb46227c6cc8b37641910833222772a");

            var rc4 = new RC4Cipher(128);
            rc4.Init(new RC4KeyParameter(key));

            rc4.Encrypt(input, output);

            Assert.Equal(rc4.KeySize, 16);
            Assert.Equal("720c94b63edf44e131d950ca211a5a30", HexConverter.ToHex(output));
        }
        
        [Fact]
        public void RC4_128_Decrypt_ShouldWork()
        {
            var input = HexConverter.FromHex("26077daab3c414dd9d2b79c220e4eba7");
            var output = new byte[16];

            var key = HexConverter.FromHex("ebb46227c6cc8b37641910833222772a");

            var rc4 = new RC4Cipher(128);
            rc4.Init(new RC4KeyParameter(key));

            rc4.Decrypt(input, output);

            Assert.Equal(rc4.KeySize, 16);
            Assert.Equal("540be91c8d1b503cacf2290801feb197", HexConverter.ToHex(output));
        }
    }
}
