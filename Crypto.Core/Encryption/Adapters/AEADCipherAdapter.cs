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

            Cipher.EncryptFinal(Cipher.Encrypt(input, output));
        }

        public void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityAssert.AssertBuffer(input, inputOffset, length);
            SecurityAssert.AssertBuffer(output, outputOffset, length - TagLength);

            Cipher.DecryptFinal(Cipher.Decrypt(input, output));
        }
    }
}
