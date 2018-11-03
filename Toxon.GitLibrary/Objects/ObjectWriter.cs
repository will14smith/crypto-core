using System;
using System.Buffers;
using System.IO.Compression;
using System.Threading.Tasks;
using Crypto.Core.Hashing;
using Crypto.SHA;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Toxon.GitLibrary.Objects
{
    public static class ObjectWriter
    {
        private static readonly ReadOnlyMemory<byte> ZlibHeader = new byte[] { 0x78, 0x01 };

        public static async Task<ObjectRef> WriteAsync(GitFileManager fileManager, Object obj)
        {
            var objBuffer = obj.ToBuffer();

            var digest = new SHA1Digest();
            digest.Update(objBuffer);
            var hash = SequenceExtensions.Create<byte>(digest.Digest().ToArray());

            var objectRef = new ObjectRef(hash);

            var file = await fileManager.CreateObjectAsync(objectRef);
            if (!file.HasValue) return objectRef;

            var checksum = CalculateChecksum(objBuffer);

            using (var writer = file.Value.OpenWriter())
            {
                writer.Write(ZlibHeader.Span);

                using (var zlib = new DeflateStream(writer, CompressionLevel.Optimal, true))
                {
                    zlib.Write(objBuffer);
                }

                writer.Write(checksum);
            }

            return objectRef;
        }

        private static byte[] CalculateChecksum(in ReadOnlySequence<byte> buffer)
        {
            ushort s1 = 1;
            ushort s2 = 0;

            foreach (var segment in buffer)
            {
                foreach (var x in segment.Span)
                {
                    s1 = (ushort)((s1 + x) % 65521);
                    s2 = (ushort)((s2 + s1) % 65521);
                }
            }

            var s = s2 << 16 | s1;

            return EndianBitConverter.Big.GetBytes(s);
        }
    }
}
