using System;
using System.Linq;
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

        public virtual void Update(ReadOnlySpan<byte> input)
        {
            var workBuffer = _workBuffer.AsSpan();
            
            while (input.Length > 0)
            {
                SecurityAssert.Assert(_workBufferLength < BlockSize / 8);

                var lengthToTake = Math.Min(input.Length, _workBuffer.Length - _workBufferLength);

                var (inputToCopy, inputRemaining) = input.Split(lengthToTake);
                
                inputToCopy.CopyTo(workBuffer.Slice(_workBufferLength));
                _workBufferLength += lengthToTake;
                input = inputRemaining;

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

        public abstract void Digest(Span<byte> output);
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
