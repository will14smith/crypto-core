using System;
using System.IO;
using Crypto.Core.Signing;
using Crypto.SHA;
using Crypto.Utils;
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

        public static void Write(Stream output, PackIndexVersion1 index)
        {
            var signedStream = new SignedStream(output, new NullSignatureCipher(), new SHA1Digest());
            var writer = new EndianBinaryWriter(EndianBitConverter.Big, signedStream);

            foreach (var fanOut in index.FirstLevelFanOut.Span) writer.Write(fanOut);
            foreach (var entry in index.Entries.Span) WriteEntry(writer, entry);
            writer.Write(index.PackHash);

            writer.Flush();
            var hash = signedStream.HashAlgorithm.Digest();
            output.Write(hash);
        }

        private static void WriteEntry(EndianBinaryWriter writer, PackIndexVersion1.Entry entry)
        {
            writer.Write(entry.Offset);
            writer.Write(entry.ObjectRef.Hash);
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

        public override Option<ulong> LookupOffset(ObjectRef objectRef)
        {
            var (lowerIndex, upperIndex) = LookupBounds(objectRef);
            var entry = LookupEntry(objectRef, lowerIndex, upperIndex);
            return entry.Select(x => (ulong)x.Offset);
        }

        public override void Write(Stream output)
        {
            PackIndexVersion1Serializer.Write(output, this);
        }

        private (uint, uint) LookupBounds(ObjectRef objectRef)
        {
            var firstByte = objectRef.Hash.First.Span[0];

            var lower = firstByte > 0 ? FirstLevelFanOut.Span[firstByte - 1] : 0;
            var upper = FirstLevelFanOut.Span[firstByte];

            return (lower, upper);
        }

        private Option<Entry> LookupEntry(ObjectRef objectRef, uint lowerIndex, uint upperIndex)
        {
            // TODO this could be a binary search
            for (var i = lowerIndex; i < upperIndex; i++)
            {
                var entry = Entries.Span[(int)i];
                if (objectRef.Hash.SequenceEquals(entry.ObjectRef.Hash))
                {
                    return Option.Some(entry);
                }
            }

            return Option.None<Entry>();
        }

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