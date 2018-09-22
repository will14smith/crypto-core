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
        private byte[] _workBuffer;

        protected bool WorkBufferEmpty => _workBufferLength == 0;

        protected BlockDigest()
        {
            _workBuffer = new byte[BlockSize / 8];
        }

        protected BlockDigest(BlockDigest source) : this()
        {
            MessageSize = source.MessageSize;

            _workBufferLength = source._workBufferLength;
            source._workBuffer.ToSpan().CopyTo(_workBuffer.ToSpan());
        }

        public virtual void Update(ReadOnlySpan<byte> input)
        {
            var length = input.Length;
            var offset = 0;

            var workBuffer = _workBuffer.ToSpan();
            
            while (length > 0)
            {
                SecurityAssert.Assert(_workBufferLength < BlockSize / 8);

                var lengthToTake = Math.Min(length, _workBuffer.Length - _workBufferLength);

                // TODO make this use Span better
                input.Slice(offset, lengthToTake).CopyTo(workBuffer.Slice(_workBufferLength));

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
                workBuffer.Fill(0);
            }
        }

        public abstract ReadOnlySpan<byte> Digest();
        public virtual void Reset()
        {
            MessageSize = 0;

            _workBufferLength = 0;
            _workBuffer.ToSpan().Fill(0);
        }

        public abstract IDigest Clone();

        protected abstract void UpdateBlock(ReadOnlySpan<byte> buffer);
    }
}
