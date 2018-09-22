using System;
using System.IO;

namespace Crypto.Utils.IO
{
    public class ReadOnlyMemoryStream : Stream
    {
        private readonly ReadOnlyMemory<byte> _data;
        private int _offset;

        public ReadOnlyMemoryStream(ReadOnlyMemory<byte> data)
        {
            _data = data;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            SecurityAssert.AssertBuffer(buffer, offset, count);

            var actualCount = _offset + count > _data.Length ? _data.Length - _offset : count;
            _data.Slice(_offset, actualCount).CopyTo(buffer.AsMemory(offset, count));

            _offset += actualCount;
            return actualCount;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            switch (origin)
            {
                case SeekOrigin.Begin: break;
                case SeekOrigin.Current: offset += _offset; break;
                case SeekOrigin.End: offset = _data.Length - offset; break;

                default: throw new ArgumentOutOfRangeException(nameof(origin), origin, null);
            }

            if (offset < 0) offset = 0;
            if (offset > _data.Length) offset = _data.Length;

            _offset = (int)offset;

            return offset;
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override void Flush()
        {
            throw new NotSupportedException();
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _data.Length;

        public override long Position
        {
            get => _offset;
            set => Seek(value, SeekOrigin.Begin);
        }
    }
}
