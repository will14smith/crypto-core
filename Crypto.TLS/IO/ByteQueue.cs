using System;
using System.Collections.Generic;
using System.Threading;
using Crypto.Utils;

namespace Crypto.TLS.IO
{
    public class ByteQueue
    {
        private readonly Queue<ReadOnlyMemory<byte>> _data = new Queue<ReadOnlyMemory<byte>>();
        private int _offset;

        private readonly SemaphoreSlim _write = new SemaphoreSlim(1, 1);
        private readonly SemaphoreSlim _read = new SemaphoreSlim(0, 1);

        public ReadOnlySpan<byte> Take(int maxLength)
        {
            SecurityAssert.Assert(maxLength > 0);

            _read.Wait();

            ReadOnlyMemory<byte> result;

            var head = _data.Peek();
            if (maxLength < head.Length - _offset)
            {
                result = head.Slice(_offset, maxLength);
                
                _offset += maxLength;
            }
            else
            {
                result = _data.Dequeue();

                _offset = 0;
                _write.Release();
            }
            
            return result.Span;
        }

        public void Put(ReadOnlyMemory<byte> data)
        {
            _write.Wait();

            SecurityAssert.NotNull(data);
            SecurityAssert.Assert(data.Length > 0);

            _data.Enqueue(data);
            _read.Release();
        }
    }
}
