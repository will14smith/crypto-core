using System.Text;
using Crypto.Core.Randomness;
using Crypto.EC.Encryption;
using Crypto.EC.Maths;
using Crypto.EC.Parameters;
using Crypto.SHA;
using Crypto.TLS.EC.Curves;
using Crypto.Utils;
using Xunit;

namespace Crypto.TLS.EC.Tests.Curves
{
    public class Secp256R1Tests
    {
        private static readonly ECPublicKey PublicKey = new ECPublicKey(
            Secp256R1.Parameters,
            Secp256R1.Parameters.Curve.PointFromBinary(HexConverter.FromHex("047a5de3d9d7bd62f6d6fc3cb13c691ab5073172a4a9b1b949c8134a1c1baaea72e3ca157dc740629c18d81f00328232306dac9bd0c3c9cba505df487e3350421a")));
        private static readonly ECPrivateKey PrivateKey = new ECPrivateKey(
            PublicKey,
            PublicKey.Parameters.Field.Value("6b80b6bec14d78e667048ba1411a5da4bba9f609ba13e7507bd1d2e92f1e3604".HexToBigInteger()));

        [Fact]
        public void TestSignature()
        {
            var input = Encoding.UTF8.GetBytes("Hello!");

            var ecdsa = new ECDSA(new DefaultRandomGenerator());
            ecdsa.Init(new ECCipherParameters(Secp256R1.Parameters, PrivateKey));

            var signature = ecdsa.Sign(input, new SHA256Digest(SHA256Digest.Mode.SHA256));
            var result = ecdsa.Verify(input, signature, new SHA256Digest(SHA256Digest.Mode.SHA256));

            Assert.True(result);
        }

        [Fact]
        public void TestVerify()
        {
            var input = Encoding.UTF8.GetBytes("Hello!");
            var signature = HexConverter.FromHex("3046022100cff2771c25049757d8a14e6f9a58b7e0928bafd33d7977fd194aeb14c64bd6ab022100f417bdbc4a9cb1f5cd719583b093a767c1c975e7ac5604ddd47827e2da05e8bb");

            var ecdsa = new ECDSA(new DefaultRandomGenerator());
            ecdsa.Init(new ECCipherParameters(Secp256R1.Parameters, PublicKey));

            var result = ecdsa.Verify(input, signature, new SHA256Digest(SHA256Digest.Mode.SHA256));

            Assert.True(result);
        }

    }
}
