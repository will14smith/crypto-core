using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Crypto.Core.Hashing;
using Crypto.SHA;
using Crypto.Utils;
using Crypto.Utils.IO;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary.Packs
{
    public class PackIndexBuilder
    {
        public static PackIndex Build(EndianBinaryReader reader)
        {
            // TODO assume reader has skipped the header
            var objectCount = reader.ReadUInt32();
            var objectRefOffsets = BuildObjectRefOffsets(reader.BaseStream, objectCount);
            var packHash = reader.ReadBytes(20);

            var firstLevelFanOut = new uint[256];
            var objectRefs = new ObjectRef[objectCount];
            var crc32Values = new uint[objectCount];
            var uint32Offsets = new uint[objectCount];
            var uint64Offsets = new ulong[objectRefOffsets.Count(x => (x.Item2 & 0xffffffff80000000) != 0)];

            var i = 0;
            var l = 0u;
            foreach (var (objectRef, offset, checksum) in objectRefOffsets.OrderBy(x => x.Item1.Hash, new SequenceComparer<byte>()))
            {
                for (int j = objectRef.Hash.First.Span[0]; j < firstLevelFanOut.Length; j++) firstLevelFanOut[j]++;

                objectRefs[i] = objectRef;
                crc32Values[i] = checksum;
                if ((offset & 0xffffffff80000000) == 0)
                {
                    uint32Offsets[i] = (uint)offset;
                }
                else
                {
                    uint32Offsets[i] = 0x80000000u | l;
                    uint64Offsets[l] = offset;

                    l++;
                }

                i++;
            }

            return new PackIndexVersion2(firstLevelFanOut, objectRefs, crc32Values, uint32Offsets, uint64Offsets, packHash);
        }

        private static IReadOnlyCollection<(ObjectRef, ulong, uint)> BuildObjectRefOffsets(Stream input, uint objectCount)
        {
            var objectRefOffsets = new List<(ObjectRef, ulong, uint)>();

            for (var i = 0; i < objectCount; i++)
            {
                var offset = (ulong)input.Position;
                input.Position = 0;

                // TODO handle when the index is needed
                var obj = PackFileSerializer.ReadObject(input, null, offset);
                var content = obj.ToBuffer();
                var objectRef = HashContent(content);

                // TODO calculate the checksum of the (original) packed object...
                var checksum = 0u;

                objectRefOffsets.Add((objectRef, offset, checksum));
            }

            return objectRefOffsets;
        }

        private static ObjectRef HashContent(in ReadOnlySequence<byte> content)
        {
            var digest = new SHA1Digest();
            digest.Update(content);
            var hash = SequenceExtensions.Create<byte>(digest.Digest().ToArray());

            return new ObjectRef(hash);
        }
    }

    public class SequenceComparer<T> : IComparer<ReadOnlySequence<T>>
        where T : IComparable<T>
    {
        public int Compare(ReadOnlySequence<T> x, ReadOnlySequence<T> y)
        {
            var sync = x.Length - y.Length;
            if (sync != 0) throw new NotImplementedException("Compare to default until they sync");

            // assume now x.Length == y.Length (but not the enumerator.Count...)
            if (x.Length == 0) return 0;

            var xIterator = x.GetEnumerator();
            var yIterator = y.GetEnumerator();

            // these will be true.
            xIterator.MoveNext();
            yIterator.MoveNext();

            var xCurrent = xIterator.Current;
            var yCurrent = yIterator.Current;

            while (true)
            {
                var xValue = xCurrent.Span[0];
                var yValue = yCurrent.Span[0];

                var comp = xValue.CompareTo(yValue);
                if (comp != 0) return comp;

                xCurrent = xCurrent.Slice(1);
                if (xCurrent.IsEmpty)
                {
                    if (!xIterator.MoveNext()) return 0; // must have reached the end

                    xCurrent = xIterator.Current;
                }

                yCurrent = yCurrent.Slice(1);
                if (yCurrent.IsEmpty)
                {
                    if (!yIterator.MoveNext()) throw new Exception("x should have hit this case");

                    yCurrent = yIterator.Current;
                }
            }
        }
    }
}
