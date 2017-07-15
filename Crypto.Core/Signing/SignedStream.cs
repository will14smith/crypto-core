using System;
using System.IO;
using Crypto.Core.Hashing;
using Crypto.Utils;

namespace Crypto.Core.Signing
{
    public class SignedStream : Stream
    {
        public Stream InnerStream { get; }

        public ISignatureCipher SignatureAlgorithm { get; }
        public IDigest HashAlgorithm { get; }

        public SignedStream(Stream inner, ISignatureCipher signAlgo, IDigest hashAlgo)
        {
            SecurityAssert.NotNull(inner);
            SecurityAssert.Assert(inner.CanWrite);

            InnerStream = inner;

            SecurityAssert.NotNull(signAlgo);
            SecurityAssert.NotNull(hashAlgo);

            SignatureAlgorithm = signAlgo;
            HashAlgorithm = hashAlgo;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            InnerStream.Write(buffer, offset, count);
            HashAlgorithm.Update(buffer, offset, count);
        }

        public byte[] Sign()
        {
            // no input because Write has alreday updated the hash
            return SignatureAlgorithm.Sign(new byte[0], HashAlgorithm);
        }

        public override void Flush()
        {
            InnerStream.Flush();
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => InnerStream.Length;
        public override long Position
        {
            get => InnerStream.Position;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }
    }
}

