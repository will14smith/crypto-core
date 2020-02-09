using System;
using Crypto.AES;
using Crypto.Core.Encryption;
using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;
using Xunit;

namespace Crypto.GCM.Tests
{
    public class GCMCipherTests
    {
        [Fact]
        public void TestAES128_Aligned()
        {
            var key = "ad7a2bd03eac835a6f620fdcb506b345";
            var iv = "12153524c0895e81b2c28465";
            var aad = "d609b1f056637a0d46df998d88e52e00b2c2846512153524c0895e81";

            var plaintext = "08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a0002";
            var ciphertext = "701afa1cc039c0d765128a665dab69243899bf7318ccdc81c9931da17fbe8edd7d17cb8b4c26fc81e3284f2b7fba713d";
            var tag = "4f8d55e7d3f06fd5a13c0c29b9d5b880";

            var aes = new AESCipher(128);
            var gcm = new GCMCipher(aes);

            var keyParam = new AESKeyParameter(HexConverter.FromHex(key));
            var ivParam = new IVParameter(keyParam, HexConverter.FromHex(iv));
            var aadParam = new AADParameter(ivParam, HexConverter.FromHex(aad));

            // encryption
            gcm.Init(aadParam);

            var encryptInput = HexConverter.FromHex(plaintext);
            var encryptOutput = new byte[encryptInput.Length+ gcm.TagLength];
            var encryptCipherText = encryptOutput.AsSpan(0, encryptInput.Length);
            var encryptTag = encryptOutput.AsSpan(encryptInput.Length, gcm.TagLength);
            
            gcm.EncryptAll(encryptInput, encryptOutput);
            
            Assert.Equal(ciphertext, HexConverter.ToHex(encryptCipherText));
            Assert.Equal(tag, HexConverter.ToHex(encryptTag));

            // decryption
            gcm.Init(aadParam);

            var decryptInput = HexConverter.FromHex(ciphertext + tag);
            var decryptOutput = new byte[decryptInput.Length - encryptTag.Length];

            gcm.DecryptAll(decryptInput, decryptOutput);
            
            Assert.Equal(plaintext, HexConverter.ToHex(decryptOutput));
        }
        
        [Fact]
        public void TestAES128_Unaligned()
        {
            var key = "e88aeefe8ea9b95a1faeee762eeca23b";
            var iv = "12153524c0895e81b2c28465";
            var aad = "d609b1f056637a0d46df998d88e52e00b2c2846512153524c0895e81";

            var plaintext = "08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a";
            var ciphertext = "11a985767b4173be2760737176244b74e7eb06593380b1260931ae226918d18d9cbfb469e7589829d2246fba4425";
            var tag = "4b320d8d2809e7573221ceea07b29a12";

            var aes = new AESCipher(128);
            var gcm = new GCMCipher(aes);

            var keyParam = new AESKeyParameter(HexConverter.FromHex(key));
            var ivParam = new IVParameter(keyParam, HexConverter.FromHex(iv));
            var aadParam = new AADParameter(ivParam, HexConverter.FromHex(aad));

            // encryption
            gcm.Init(aadParam);

            var encryptInput = HexConverter.FromHex(plaintext);
            var encryptOutput = new byte[encryptInput.Length + gcm.TagLength];
            var encryptCipherText = encryptOutput.AsSpan(0, encryptInput.Length);
            var encryptTag = encryptOutput.AsSpan(encryptInput.Length, gcm.TagLength);
            
            gcm.EncryptAll(encryptInput, encryptOutput);

            Assert.Equal(ciphertext, HexConverter.ToHex(encryptCipherText));
            Assert.Equal(tag, HexConverter.ToHex(encryptTag));

            // decryption
            gcm.Init(aadParam);

            var decryptInput = HexConverter.FromHex(ciphertext + tag);
            var decryptOutput = new byte[decryptInput.Length - encryptTag.Length];

            gcm.DecryptAll(decryptInput, decryptOutput);

            Assert.Equal(plaintext, HexConverter.ToHex(decryptOutput));
        }
    }
}
