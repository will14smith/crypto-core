using System;
using System.Linq;
using Crypto.Utils;
using Crypto.Utils.IO;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary.Packs
{
    public static class PackIndexVersion2Serializer
    {
        public static PackIndex Read(EndianBinaryReader reader)
        {
            var fanOut = new uint[256];
            for (var i = 0; i < fanOut.Length; i++) fanOut[i] = reader.ReadUInt32();

            var itemCount = (int)fanOut[255];

            var objectRefs = new ObjectRef[itemCount];
            for (var i = 0; i < itemCount; i++) objectRefs[i] = new ObjectRef(reader.ReadBytes(20));

            var crc32Values = new uint[itemCount];
            for (var i = 0; i < itemCount; i++) crc32Values[i] = reader.ReadUInt32();

            var uint32Offsets = new uint[itemCount];
            for (var i = 0; i < itemCount; i++) uint32Offsets[i] = reader.ReadUInt32();

            var uint64OffsetCount = uint32Offsets.Count(x => (x & 0x80000000) != 0);
            var uint64Offsets = new ulong[uint64OffsetCount];
            for (var i = 0; i < uint64OffsetCount; i++) uint64Offsets[i] = reader.ReadUInt64();

            var packHash = reader.ReadBytes(20);
            var indexHash = reader.ReadBytes(20);
            // TODO verify index hash

            return new PackIndexVersion2(fanOut, objectRefs, crc32Values, uint32Offsets, uint64Offsets, packHash);
        }
    }

    public class PackIndexVersion2 : PackIndex
    {
        public PackIndexVersion2(ReadOnlyMemory<uint> firstLevelFanOut, ReadOnlyMemory<ObjectRef> objectRefs, ReadOnlyMemory<uint> crc32Values, ReadOnlyMemory<uint> uint32Offsets, ReadOnlyMemory<ulong> uint64Offsets, ReadOnlyMemory<byte> packHash)
            : base(packHash)
        {
            FirstLevelFanOut = firstLevelFanOut;
            ObjectRefs = objectRefs;
            Crc32Values = crc32Values;
            Uint32Offsets = uint32Offsets;
            Uint64Offsets = uint64Offsets;
        }

        public ReadOnlyMemory<uint> FirstLevelFanOut { get; }
        public ReadOnlyMemory<ObjectRef> ObjectRefs { get; }
        public ReadOnlyMemory<uint> Crc32Values { get; }
        public ReadOnlyMemory<uint> Uint32Offsets { get; }
        public ReadOnlyMemory<ulong> Uint64Offsets { get; }

        public override Option<ulong> LookupOffset(ObjectRef objectRef)
        {
            var (lowerIndex, upperIndex) = LookupBounds(objectRef);
            var index = LookupIndex(objectRef, lowerIndex, upperIndex);
            if (!index.HasValue) return Option.None<ulong>();

            var offset32 = Uint32Offsets.Span[(int)index.Value];
            if ((offset32 & 0x80000000) == 0) return Option.Some<ulong>(offset32);

            var offset64 = Uint64Offsets.Span[(int)(offset32 & 0x7fffffff)];
            return Option.Some(offset64);
        }

        private (uint, uint) LookupBounds(ObjectRef objectRef)
        {
            var firstByte = objectRef.Hash.First.Span[0];

            var lower = firstByte > 0 ? FirstLevelFanOut.Span[firstByte - 1] : 0;
            var upper = FirstLevelFanOut.Span[firstByte];

            return (lower, upper);
        }

        private Option<uint> LookupIndex(ObjectRef objectRef, uint lowerIndex, uint upperIndex)
        {
            // TODO this could be a binary search
            for (var i = lowerIndex; i < upperIndex; i++)
            {
                var indexRef = ObjectRefs.Span[(int)i];
                if (objectRef.Hash.SequenceEquals(indexRef.Hash)) return Option.Some(i);
            }

            return Option.None<uint>();
        }
    }
}