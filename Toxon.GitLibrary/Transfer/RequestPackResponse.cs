using System;
using System.Buffers;
using System.IO;
using System.Text;
using Crypto.Utils;
using Crypto.Utils.IO;
using Toxon.GitLibrary.Packs;

namespace Toxon.GitLibrary.Transfer
{
    public class RequestPackResponse
    {
        private static readonly ReadOnlyMemory<byte> Pack = Encoding.UTF8.GetBytes("PACK");

        public ReadOnlySequence<byte> PackFile { get; }

        public RequestPackResponse(ReadOnlySequence<byte> packFile)
        {
            PackFile = packFile;

            using (var stream = new MemoryStream(packFile.ToArray()))
            {
                stream.Position = 8;

                var index = PackIndexBuilder.Build(new EndianBinaryReader(EndianBitConverter.Big, stream));
            }
        }

        public static RequestPackResponse Parse(ReadOnlySequence<byte> content)
        {
            while (true)
            {
                if (content.StartsWith(Pack.Span))
                {
                    return new RequestPackResponse(content);
                }

                (_, content) = TransferRecord.Read(content);
            }
        }
    }
}