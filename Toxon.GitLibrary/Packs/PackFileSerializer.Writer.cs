using System;
using System.IO;
using Crypto.Core.Signing;
using Crypto.SHA;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Toxon.GitLibrary.Packs
{
    public partial class PackFileSerializer
    {
        public static void Write(Stream output, PackFile pack)
        {
            // TODO compress objects using deltas (needs to be done by whatever is building the PackFiles)
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

        private static void WriteObject(EndianBinaryWriter writer, PackObject obj)
        {
            var length = obj.Content.Length;
            WriteTypeAndLength(writer, obj.Type, length);

            switch (obj.Type)
            {
                case PackObjectType.Commit:
                case PackObjectType.Tree:
                case PackObjectType.Blob:
                case PackObjectType.Tag: break;

                case PackObjectType.OfsDelta: throw new NotImplementedException();
                case PackObjectType.RefDelta:
                    writer.Write(((PackObject.RefDelta)obj).ObjectRef.Hash);
                    break;

                default:
                    throw new ArgumentOutOfRangeException();
            }

            Zlib.Deflate(writer.BaseStream, obj.Content);
        }

        private static void WriteTypeAndLength(EndianBinaryWriter writer, PackObjectType type, long length)
        {
            byte b = 0;

            b |= (byte)(((byte)type & 0b111) << 4);
            b |= (byte)(length & 0xf);
            length >>= 4;

            while (length != 0)
            {
                writer.Write((byte)(b | 0x80));

                b = (byte)(length & 0x7f);
                length >>= 7;
            }

            writer.Write(b);
        }

    }
}