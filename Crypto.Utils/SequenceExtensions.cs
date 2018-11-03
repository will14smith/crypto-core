using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Crypto.Utils
{
    public static class SequenceExtensions
    {
        public static void AddRange<T>(this IList<ReadOnlyMemory<T>> items, ReadOnlySequence<T> sequence)
        {
            if (sequence.IsSingleSegment)
            {
                items.Add(sequence.First);
            }
            else
            {
                foreach (var segment in sequence)
                {
                    items.Add(segment);
                }
            }
        }

        public static ReadOnlySequence<T> ToSequence<T>(this IReadOnlyList<ReadOnlyMemory<T>> items)
        {
            if (items == null || items.Count == 0) throw new ArgumentException(nameof(items));

            var startSegment = new MemorySequenceSegment<T>(items[0]);
            var endSegment = startSegment;
            for (var i = 1; i < items.Count; i++)
            {
                endSegment = endSegment.Add(items[i]);
            }

            return new ReadOnlySequence<T>(startSegment, 0, endSegment, endSegment.Memory.Length);
        }

        public static ReadOnlySequence<T> Create<T>(params ReadOnlyMemory<T>[] items)
        {
            return items.ToSequence();
        }

        public static ReadOnlySequence<T> Concat<T>(this ReadOnlySequence<T> head, params ReadOnlySequence<T>[] tails)
        {
            return Concat(head, (IReadOnlyCollection<ReadOnlySequence<T>>)tails);
        }

        public static ReadOnlySequence<T> Concat<T>(this ReadOnlySequence<T> head, IReadOnlyCollection<ReadOnlySequence<T>> tails)
        {
            var headEnumerator = head.GetEnumerator();
            if (!headEnumerator.MoveNext()) throw new NotImplementedException();

            var startSegment = new MemorySequenceSegment<T>(headEnumerator.Current);
            var endSegment = startSegment;

            while (headEnumerator.MoveNext())
            {
                endSegment = endSegment.Add(headEnumerator.Current);
            }

            foreach (var tail in tails)
            {
                var tailEnumerator = tail.GetEnumerator();
                while (tailEnumerator.MoveNext())
                {
                    endSegment = endSegment.Add(tailEnumerator.Current);
                }
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool StartsWith<T>(in this ReadOnlySequence<T> source, ReadOnlySpan<T> value) where T : IEquatable<T>
        {
            if (source.Length < value.Length)
                return false;

            return source.IsSingleSegment
                ? source.First.Span.StartsWith(value)
                : StartsWithMultiSegment(source, value);
        }

        private static bool StartsWithMultiSegment<T>(in ReadOnlySequence<T> source, ReadOnlySpan<T> value) where T : IEquatable<T>
        {
            foreach (var segment in source)
            {
                if (!segment.Span.StartsWith(value))
                {
                    return false;
                }

                value = value.Slice(segment.Length);
                if (value.IsEmpty)
                {
                    return true;
                }
            }

            return true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static SequencePosition? PositionOf<T>(in this ReadOnlySequence<T> source, ReadOnlySpan<T> value) where T : IEquatable<T>
        {
            if (source.IsEmpty || value.IsEmpty)
                return null;

            if (source.IsSingleSegment)
            {
                var index = source.First.Span.IndexOf(value);
                if (index > -1)
                    return source.GetPosition(index);
                else
                    return null;
            }

            return PositionOfMultiSegment(source, value);
        }

        public static SequencePosition? PositionOfMultiSegment<T>(in ReadOnlySequence<T> source, ReadOnlySpan<T> value) where T : IEquatable<T>
        {
            var firstVal = value[0];

            SequencePosition position = source.Start;
            SequencePosition result = position;
            while (source.TryGet(ref position, out ReadOnlyMemory<T> memory))
            {
                var offset = 0;
                while (offset < memory.Length)
                {
                    var index = memory.Span.Slice(offset).IndexOf(firstVal);
                    if (index == -1)
                        break;

                    var candidatePos = source.GetPosition(index + offset, result);
                    if (source.MatchesFrom(value, candidatePos))
                        return candidatePos;

                    offset += index + 1;
                }
                if (position.GetObject() == null)
                {
                    break;
                }

                result = position;
            }

            return null;
        }


        public static bool MatchesFrom<T>(in this ReadOnlySequence<T> source, ReadOnlySpan<T> value, SequencePosition? position = null) where T : IEquatable<T>
        {
            var candidate = position == null ? source : source.Slice(position.Value, value.Length);
            if (candidate.Length != value.Length)
                return false;

            int i = 0;
            foreach (var sequence in candidate)
            {
                foreach (var entry in sequence.Span)
                {
                    if (!entry.Equals(value[i++]))
                        return false;
                }
            }
            return true;
        }

    }
}
