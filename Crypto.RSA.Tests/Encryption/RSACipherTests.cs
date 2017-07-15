using Crypto.Certificates.Keys;
using Crypto.RSA.Keys;
using System;
using System.Text;
using Crypto.Certificates.Parameters;
using Crypto.Core.Randomness;
using Crypto.RSA.Encryption;
using Xunit;
using Crypto.SHA;
using Crypto.Utils;

namespace Crypto.RSA.Tests.Encryption
{
    public class RSACipherTests
    {
        private static readonly PrivateKey Key = new RSAKeyReader().ReadPrivateKey(null, Convert.FromBase64String("MIIBOwIBAAJBAMrK7ObRkpDkRgfjPRN2fFhVvfHByK4VCo+X7qOmcaYdP1ekHXfOQYcwwPLUwM6iZoYM0QGpGoJLJiJeWM8rkpECAwEAAQJAewlXZktsk0AMRSjXm4Fdu/J5hb4+1W+qsqhJfzyy40byZW1RVZ6nf9VQwg21sB0PCPZpPqwDR8582BAd4VQcqQIhAPLoGNX9CRxBfNzuHiP3k+vMOCC3lVpPp7CGVm629+azAiEA1blKT9FNEF7R2cxmn/HImn4MWlgG/YfBIsVLVjXOI6sCIQCzXiQI0CLMFKepVMQ49vbp5hGER0woNi2zsl9cvgts9QIhAMqyrTP+QaShCU4TedGAMs2zdmvIyPhzZE1h6Q2egh95AiA+MprDyZjZ+zjqgSD/Kkp82vSy04iF5ZBvrBhtS0vK0Q=="));

        [Fact]
        public void EncryptDecrypt_ShouldRoundTrip()
        {
            var input = new byte[] { 0, 1, 5, 30, 244, 255, 193 };

            var rsa = new RSACipher(new DefaultRandomGenerator());
            rsa.Init(new PrivateKeyParameter(Key));

            var encryptOutput = new byte[rsa.KeySize];
            var decryptOutput = new byte[input.Length];

            rsa.Encrypt(input, 0, encryptOutput, 0, input.Length);
            rsa.Decrypt(encryptOutput, 0, decryptOutput, 0, encryptOutput.Length);

            Assert.Equal(input, decryptOutput);
        }

        [Fact]
        public void SignVerify_ShouldRoundTrip()
        {
            var input = Encoding.UTF8.GetBytes("Hello World");

            var rsa = new RSASignatureCipher();
            rsa.Init(new PrivateKeyParameter(Key));

            var signature = rsa.Sign(input, new SHA1Digest());

            Assert.True(rsa.Verify(input, signature, new SHA1Digest()));
            Assert.Equal("54eab8c1837f4ded1122e1fbf47d0225188148a092e180e83b489aba1f1dc7b5" +
                            "241103ba8f136b393cf8c054a6a69e0c372453aa098e091a2dbe0310f0b653cb", HexConverter.ToHex(signature));
        }
        
        [Fact]
        public void SignVerify_InvalidSignature_ShouldNotVerify()
        {
            var input = Encoding.UTF8.GetBytes("Hello World");

            var rsa = new RSASignatureCipher();
            rsa.Init(new PrivateKeyParameter(Key));

            var signature = rsa.Sign(input, new SHA1Digest());

            signature[signature.Length - 1] ^= 1;

            Assert.False(rsa.Verify(input, signature, new SHA1Digest()));
        }
    }
}
