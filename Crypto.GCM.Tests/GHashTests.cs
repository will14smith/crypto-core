using Crypto.Utils;
using Xunit;

namespace Crypto.GCM.Tests
{
    public class GHashTests
    {
        [Fact]
        public void TestAES128()
        {
            var key = "dfa6bf4ded81db03ffcaff95f830f061";
            var input = "952b2a56a5604ac0b32b6656a05b40b6";
            var expected = "da53eb0ad2c55bb64fc4802cc3feda60";

            var hash = new GHash(HexConverter.FromHex(key));

            var hashInput = HexConverter.FromHex(input);
            hash.Update(hashInput, 0, hashInput.Length);
            var hashOutput = hash.Digest();

            Assert.Equal(expected, HexConverter.ToHex(hashOutput));
        }
    }
}
