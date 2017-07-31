using System;
using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.Core.Encryption
{
    public class NullCipher : ICipher
    {
        public int KeySize => 0;

        public void Init(ICipherParameters parameters)
        {
        }

        public void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityAssert.AssertBuffer(input, inputOffset, length);
            SecurityAssert.AssertBuffer(output, outputOffset, length);

            Array.Copy(input, inputOffset, output, outputOffset, length);
        }

        public void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityAssert.AssertBuffer(input, inputOffset, length);
            SecurityAssert.AssertBuffer(output, outputOffset, length);

            Array.Copy(input, inputOffset, output, outputOffset, length);
        }
    }
}
