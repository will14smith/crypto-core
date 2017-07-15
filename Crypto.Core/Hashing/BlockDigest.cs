using System;
using Crypto.ASN1;
using Crypto.Utils;

namespace Crypto.Core.Hashing
{
    /// <summary>
    /// Sizes are in bits, Lengths in bytes
    /// </summary>
    public abstract class BlockDigest : IDigest
    {
        public abstract ASN1ObjectIdentifier Id { get; }
        public abstract int BlockSize { get; }
        public abstract int HashSize { get; }

        protected long MessageSize { get; private set; }

        private int _workBufferLength;
        private readonly byte[] _workBuffer;

        protected bool WorkBufferEmpty => _workBufferLength == 0;

        protected BlockDigest()
        {
            _workBuffer = new byte[BlockSize / 8];
        }

        protected BlockDigest(BlockDigest source) : this()
        {
            MessageSize = source.MessageSize;

            _workBufferLength = source._workBufferLength;
            Array.Copy(source._workBuffer, _workBuffer, _workBufferLength);
        }

        public virtual void Update(byte[] buffer, int offset, int length)
        {
            SecurityAssert.NotNull(buffer);
            SecurityAssert.Assert(offset >= 0 && length >= 0);
            SecurityAssert.Assert(offset + length <= buffer.Length);

            while (length > 0)
            {
                SecurityAssert.Assert(_workBufferLength < BlockSize / 8);

                var lengthToTake = Math.Min(length, _workBuffer.Length - _workBufferLength);

                Array.Copy(buffer, offset, _workBuffer, _workBufferLength, lengthToTake);

                length -= lengthToTake;
                offset += lengthToTake;
                _workBufferLength += lengthToTake;

                MessageSize += lengthToTake * 8;

                SecurityAssert.Assert(_workBufferLength <= BlockSize / 8);

                if (_workBufferLength != BlockSize / 8)
                {
                    continue;
                }

                UpdateBlock(_workBuffer);

                _workBufferLength = 0;
                Array.Clear(_workBuffer, 0, _workBuffer.Length);
            }
        }

        public abstract byte[] Digest();
        public virtual void Reset()
        {
            MessageSize = 0;

            _workBufferLength = 0;
            Array.Clear(_workBuffer, 0, _workBuffer.Length);
        }

        public abstract IDigest Clone();

        protected abstract void UpdateBlock(byte[] buffer);
    }
}
