using System;
using Crypto.Core.Encryption.Parameters;
using Crypto.Core.Hashing;

namespace Crypto.Core.Signing
{
    public class NullSignatureCipher : ISignatureCipher
    {
        public void Init(ICipherParameters parameters)
        {
            throw new NotSupportedException();
        }

        public byte[] Sign(byte[] input, IDigest hash)
        {
            throw new NotSupportedException();
        }

        public bool Verify(byte[] input, byte[] signature, IDigest hash)
        {
            throw new NotSupportedException();
        }
    }
}
