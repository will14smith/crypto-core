using System;
using Crypto.Core.Encryption.Parameters;

namespace Crypto.Core.Encryption
{
    public class NullCipher : ICipher
    {
        public int KeySize => 0;

        public void Init(ICipherParameters parameters)
        {
            throw new NotImplementedException();
        }

        public void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            throw new NotImplementedException();
        }

        public void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            throw new NotImplementedException();
        }
    }
}
