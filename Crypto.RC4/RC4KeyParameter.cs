using System;
using Crypto.Core.Encryption.Parameters;

namespace Crypto.RC4
{
    public class RC4KeyParameter : ICipherParameters
    {
        public RC4KeyParameter(ReadOnlySpan<byte> key)
        {
            Key = key.ToArray();
        }

        public ReadOnlyMemory<byte> Key { get; }
    }
}
