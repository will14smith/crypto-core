using System;
using System.IO;
using Crypto.Utils.IO;

namespace Toxon.GitLibrary.Packs
{
    public class PackIndexSerializer
    {
        public static PackIndex Read(Stream input)
        {
            var reader = new EndianBinaryReader(EndianBitConverter.Big, input);

            var first = reader.ReadUInt32();
            if (first != 0xff744f63) return PackIndexVersion1Serializer.Read(reader, first);

            var version = reader.ReadUInt32();
            if (version != 2) throw new Exception("unsupported version");

            return PackIndexVersion2Serializer.Read(reader);
        }
    }

    public abstract class PackIndex
    {
        protected PackIndex(ReadOnlyMemory<byte> packHash)
        {
            PackHash = packHash;
        }

        public ReadOnlyMemory<byte> PackHash { get; }
    }
}
