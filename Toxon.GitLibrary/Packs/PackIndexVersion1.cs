using System;
using Crypto.Utils.IO;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary.Packs
{
    public static class PackIndexVersion1Serializer
    {
        public static PackIndex Read(EndianBinaryReader reader, uint first)
        {
            var fanOut = new uint[256];
            fanOut[0] = first;
            for (var i = 1; i < fanOut.Length; i++) fanOut[i] = reader.ReadUInt32();

            var entries = new PackIndexVersion1.Entry[fanOut[255]];
            for (var i = 0; i < entries.Length; i++)
            {
                entries[i] = ReadEntry(reader);
            }

            var packHash = reader.ReadBytes(20);
            var indexHash = reader.ReadBytes(20);
            // TODO verify index hash

            return new PackIndexVersion1(fanOut, entries, packHash);
        }

        private static PackIndexVersion1.Entry ReadEntry(EndianBinaryReader reader)
        {
            var offset = reader.ReadUInt32();
            var objectRef = new ObjectRef(reader.ReadBytes(20));

            return new PackIndexVersion1.Entry(offset, objectRef);
        }
    }

    public class PackIndexVersion1 : PackIndex
    {
        public PackIndexVersion1(ReadOnlyMemory<uint> firstLevelFanOut, ReadOnlyMemory<Entry> entries, ReadOnlyMemory<byte> packHash)
            : base(packHash)
        {
            FirstLevelFanOut = firstLevelFanOut;
            Entries = entries;
        }

        public ReadOnlyMemory<uint> FirstLevelFanOut { get; }
        public ReadOnlyMemory<Entry> Entries { get; }

        public class Entry
        {
            public Entry(uint offset, ObjectRef objectRef)
            {
                Offset = offset;
                ObjectRef = objectRef;
            }

            public uint Offset { get; }
            public ObjectRef ObjectRef { get; }
        }
    }
}