using System;
using System.Buffers;

namespace Crypto.Utils
{
    public static class SequenceExtensions
    {
        public static ReadOnlySequence<T> Create<T>(params ReadOnlyMemory<T>[] items)
        {
            if (items == null || items.Length == 0) throw new ArgumentException(nameof(items));

            var startSegment = new MemorySequenceSegment<T>(items[0]);
            var endSegment = startSegment;
            for (var i = 1; i < items.Length; i++)
            {
                endSegment = endSegment.Add(items[i]);
            }

            return new ReadOnlySequence<T>(startSegment, 0, endSegment, endSegment.Memory.Length);
        }

        private class MemorySequenceSegment<T> : ReadOnlySequenceSegment<T>
        {
            public MemorySequenceSegment(ReadOnlyMemory<T> memory)
                => Memory = memory;

            public MemorySequenceSegment<T> Add(ReadOnlyMemory<T> mem)
            {
                var segment = new MemorySequenceSegment<T>(mem)
                {
                    RunningIndex = RunningIndex + Memory.Length,
                };

                Next = segment;
                return segment;
            }
        }
    }
}
