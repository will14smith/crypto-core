using System;
using Crypto.ASN1;

namespace Crypto.Core.Hashing
{
    class NullDigest : IDigest
    {
        public ASN1ObjectIdentifier Id => null;
        public int BlockSize => 0;
        public int HashSize => 0;

        public void Update(ReadOnlySpan<byte> buffer)
        {
            throw new NotImplementedException();
        }

        public ReadOnlySpan<byte> Digest()
        {
            throw new NotImplementedException();
        }

        public void Reset()
        {
            throw new NotImplementedException();
        }

        public IDigest Clone()
        {
            throw new NotImplementedException();
        }
    }
}
