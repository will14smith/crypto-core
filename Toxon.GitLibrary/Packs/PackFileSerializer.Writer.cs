using System;
using System.IO;
using Crypto.Core.Signing;
using Crypto.SHA;
using Crypto.Utils;
using Crypto.Utils.IO;
using Toxon.GitLibrary.Objects;
using Object = Toxon.GitLibrary.Objects.Object;

namespace Toxon.GitLibrary.Packs
{
    public partial class PackFileSerializer
    {
        public static void Read(Stream output, PackFile pack)
        {
            // TODO compress objects using deltas

            var signedStream = new SignedStream(output, new NullSignatureCipher(), new SHA1Digest());
            var writer = new EndianBinaryWriter(EndianBitConverter.Big, signedStream);

            WriteHeader(writer, pack);

            writer.Write(pack.Objects.Count);
            foreach (var obj in pack.Objects)
            {
                WriteObject(writer, obj);
            }

            writer.Flush();
            var hash = signedStream.HashAlgorithm.Digest();
            output.Write(hash);
        }

        private static void WriteHeader(EndianBinaryWriter writer, PackFile pack)
        {
            var version = 2u;

            writer.Write(Signature.Span);
            writer.Write(version);
        }

        private static void WriteObject(EndianBinaryWriter writer, Object obj)
        {
            var objBuffer = obj.ToBuffer();

            var type = ObjectToPackType(obj.Type);
            var length = objBuffer.Length;
            WriteTypeAndLength(writer, type, length);

            Zlib.Deflate(writer.BaseStream, objBuffer);
        }

        private static PackObjectType ObjectToPackType(ObjectType type)
        {
            switch (type)
            {
                case ObjectType.Blob: return PackObjectType.Blob;
                case ObjectType.Commit: return PackObjectType.Commit;
                case ObjectType.Tree: return PackObjectType.Tree;

                default: throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        private static void WriteTypeAndLength(EndianBinaryWriter writer, PackObjectType type, long length)
        {
            byte b = 0;

            b |= (byte)(((byte)type & 0b111) << 4);
            b |= (byte)(length & 0xf);
            length >>= 4;

            while (length != 0)
            {
                writer.Write(b | 0x80);

                b = (byte)(length & 0x7f);
                length >>= 7;
            }

            writer.Write(b);
        }

    }
}