using System;
using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.Core.Encryption.Adapters
{
    public class AEADCipherAdapter : ICipher
    {
        public IAEADBlockCipher Cipher { get; }

        public AEADCipherAdapter(IAEADBlockCipher cipher)
        {
            Cipher = cipher;
        }

        public int KeySize => Cipher.KeySize;
        public int BlockLength => Cipher.BlockLength;
        public int TagLength => Cipher.TagLength;

        public void Init(ICipherParameters parameters)
        {
            Cipher.Init(parameters);
        }

        public void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityAssert.AssertBuffer(input, inputOffset, length);
            SecurityAssert.AssertBuffer(output, outputOffset, length + TagLength);

            var tag = new byte[TagLength];
            
            var offset = Cipher.Encrypt(input, inputOffset, output, outputOffset, length);
            offset += Cipher.EncryptFinal(output, outputOffset + offset, tag);
            Array.Copy(tag, 0, output, outputOffset + offset, tag.Length);
        }

        public void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityAssert.AssertBuffer(input, inputOffset, length);
            SecurityAssert.AssertBuffer(output, outputOffset, length - TagLength);

            var offset = Cipher.Decrypt(input, inputOffset, output, outputOffset, length);
            Cipher.DecryptFinal(input, inputOffset + offset, output, outputOffset + offset);
        }
    }
}
