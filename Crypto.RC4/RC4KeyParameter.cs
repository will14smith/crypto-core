using System;
using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.RC4
{
    public class RC4KeyParameter : ICipherParameters
    {
        public RC4KeyParameter(byte[] key)
        {
            SecurityAssert.NotNull(key);

            Key = new byte[key.Length];
            Array.Copy(key, Key, key.Length);
        }
        public RC4KeyParameter(byte[] key, int offset, int length)
        {
            SecurityAssert.AssertBuffer(key, offset, length);

            Key = new byte[length];
            Array.Copy(key, offset, Key, 0, length);
        }

        public byte[] Key { get; }
    }
}
