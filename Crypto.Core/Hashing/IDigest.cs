using System;
using Crypto.ASN1;

namespace Crypto.Core.Hashing
{
    public interface IDigest
    {
        ASN1ObjectIdentifier Id { get; }

        int BlockSize { get; }
        int HashSize { get; }

        void Update(ReadOnlySpan<byte> input);
        void Digest(Span<byte> output);

        void Reset();

        IDigest Clone();
    }
}
