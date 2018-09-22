using System;
using Crypto.Core.Encryption.Parameters;

namespace Crypto.AES
{
    public class AESKeyParameter : ICipherParameters
    {
        public AESKeyParameter(ReadOnlySpan<byte> key)
        {
            Key = key.ToArray();
        }

        public ReadOnlyMemory<byte> Key { get; }
    }
}
