using System;
using System.Collections.Generic;
using System.Threading;
using Crypto.Utils;

namespace Crypto.TLS.IO
{
    public class ByteQueue
    {
        private readonly Queue<byte[]> _data = new Queue<byte[]>();
        private int _offset;

        private readonly SemaphoreSlim _write = new SemaphoreSlim(1, 1);
        private readonly SemaphoreSlim _read = new SemaphoreSlim(0, 1);

        public byte[] Take(int maxLength)
        {
            SecurityAssert.Assert(maxLength > 0);

            _read.Wait();

            byte[] result;

            var head = _data.Peek();
            if (maxLength < head.Length - _offset)
            {
                result = new byte[maxLength];
                Array.Copy(head, _offset, result, 0, maxLength);

                _offset += maxLength;
            }
            else
            {
                result = _data.Dequeue();

                _offset = 0;
                _write.Release();
            }


            return result;
        }

        public void Put(byte[] data)
        {
            _write.Wait();

            SecurityAssert.NotNull(data);
            SecurityAssert.Assert(data.Length > 0);

            _data.Enqueue(data);
            _read.Release();
        }
    }
}
