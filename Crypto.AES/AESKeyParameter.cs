using System;
using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.AES
{
    public class AESKeyParameter : ICipherParameters
    {
        public AESKeyParameter(byte[] key)
        {
            SecurityAssert.NotNull(key);

            Key = new byte[key.Length];
            Array.Copy(key, Key, key.Length);
        }
        public AESKeyParameter(byte[] key, int offset, int length)
        {
            SecurityAssert.AssertBuffer(key, offset, length);

            Key = new byte[length];
            Array.Copy(key, offset, Key, 0, length);
        }

        public byte[] Key { get; }
    }
}
