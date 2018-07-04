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

        public ReadOnlySpan<byte> Sign(ReadOnlySpan<byte> input, IDigest hash)
        {
            throw new NotImplementedException();
        }

        public bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature, IDigest hash)
        {
            throw new NotImplementedException();
        }
    }
}
