using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Crypto.Core.Hashing;
using Crypto.SHA;
using Crypto.Utils;
using Crypto.Utils.IO;
using Toxon.GitLibrary.Objects;
using Crc32 = Crypto.Utils.Crc32;

namespace Toxon.GitLibrary.Packs
{
    public class PackIndexBuilder
    {
        public static PackIndex Build(EndianBinaryReader reader)
        {
            // TODO assume reader has skipped the header
            var objectCount = reader.ReadUInt32();
            var packObjects = ReadPackObjects(reader.BaseStream, objectCount);
            var packHash = reader.ReadBytes(20);

            var objectRefOffsets = ReadObjects(reader.BaseStream, packObjects);

            var firstLevelFanOut = new uint[256];
            var objectRefs = new ObjectRef[objectCount];
            var crc32Values = new uint[objectCount];
            var uint32Offsets = new uint[objectCount];
            var uint64Offsets = new ulong[objectRefOffsets.Count(x => (x.Item2 & 0xffffffff80000000) != 0)];

            var i = 0;
            var l = 0u;
            foreach (var (objectRef, offset) in objectRefOffsets.OrderBy(x => x.Item1.Hash, new SequenceComparer<byte>()))
            {
                for (int j = objectRef.Hash.First.Span[0]; j < firstLevelFanOut.Length; j++) firstLevelFanOut[j]++;

                objectRefs[i] = objectRef;
                crc32Values[i] = CalculateChecksum(reader.BaseStream, offset, GetPackObjectSize(offset, objectRefOffsets.Select(x => x.Item2)));
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

        private static ulong? GetPackObjectSize(ulong objectOffset, IEnumerable<ulong> objectOffsets)
        {
            var nextObjectOffset = objectOffsets.Where(x => x > objectOffset).OrderBy(x => x).FirstOrDefault();
            if (nextObjectOffset == default)
            {
                return null;
            }

            return nextObjectOffset - objectOffset;
        }

        private static uint CalculateChecksum(Stream input, ulong offset, ulong? size)
        {
            if (size == null)
            {
                // EOF - 20 for SHA1
                size = (ulong) input.Length - offset - 20;
            }

            var savedInputOffset = input.Position;
            input.Position = (long)offset;

            var buffer = input.ReadExactly((int)size.Value);
            var checksum = Crc32.Checksum(buffer);

            input.Position = savedInputOffset;

            return checksum;
        }

        private static IReadOnlyCollection<(PackObject, ulong)> ReadPackObjects(Stream input, uint objectCount)
        {
            var objects = new (PackObject, ulong)[objectCount];

            for (var i = 0; i < objectCount; i++)
            {
                var offset = (ulong)input.Position;
                input.Position = 0;

                var obj = PackFileSerializer.ReadObject(input, offset);

                objects[i] = (obj, offset);
            }

            return objects;
        }

        private static IReadOnlyCollection<(ObjectRef, ulong)> ReadObjects(Stream packStream, IReadOnlyCollection<(PackObject, ulong)> packObjects)
        {
            var results = new List<(ObjectRef, ulong)>();
            Option<ulong> PackIndexLookup(ObjectRef objectRef)
            {
                var result = results.FindIndex(x => x.Item1.Hash.SequenceEquals(objectRef.Hash));

                return result != -1 ? Option.Some(results[result].Item2) : Option.None<ulong>();
            }

            var queue = new Queue<(PackObject, ulong)>(packObjects);
            var ttl = queue.Count;

            while (queue.Count > 0)
            {
                var (packObject, offset) = queue.Dequeue();

                var objectOpt = PackFileResolver.ReadObject(packStream, PackIndexLookup, packObject);
                if (!objectOpt.HasValue)
                {
                    if (ttl-- == 0) throw new Exception("infinite cycle");
                    // try again after parsing some other objects
                    queue.Enqueue((packObject, offset));
                }
                else
                {
                    ttl = queue.Count;

                    var (type, content) = objectOpt.Value;
                    string header;
                    switch (type)
                    {
                        case ObjectType.Blob: header = "blob " + content.Length + "\0"; break;
                        case ObjectType.Commit: header = "commit " + content.Length + "\0"; break;
                        case ObjectType.Tree: header = "tree " + content.Length + "\0"; break;
                        default: throw new ArgumentOutOfRangeException();
                    }

                    var headerBuffer = new ReadOnlyMemory<byte>[] { Encoding.UTF8.GetBytes(header) }.ToSequence();

                    var objContent = headerBuffer.Concat(content);
                    var hash = HashContent(objContent);
                    results.Add((hash, offset));
                }
            }

            return results;
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
