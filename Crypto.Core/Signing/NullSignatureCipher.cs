using System;
using Crypto.Core.Encryption.Parameters;
using Crypto.Core.Hashing;

namespace Crypto.Core.Signing
{
    public class NullSignatureCipher : ISignatureCipher
    {
        public int KeySize => 0;

        public void Init(ICipherParameters parameters)
        {
            throw new NotImplementedException();
        }

        public byte[] Sign(byte[] input, IDigest hash)
        {
            throw new NotImplementedException();
        }

        public bool Verify(byte[] input, byte[] signature, IDigest hash)
        {
            throw new NotImplementedException();
        }
    }
}
