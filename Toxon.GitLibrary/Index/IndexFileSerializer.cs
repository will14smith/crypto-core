using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Crypto.Core.Signing;
using Crypto.SHA;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Toxon.GitLibrary.Index
{
    public class IndexFileSerializer
    {
        private static readonly ReadOnlyMemory<byte> Header = Encoding.UTF8.GetBytes("DIRC");
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1);

        private readonly GitFileManager _fileManager;

        public IndexFileSerializer(GitFileManager fileManager)
        {
            _fileManager = fileManager;
        }

        public async Task<IndexFile> ReadAsync()
        {
            var indexFile = await _fileManager.GetRootFileAsync("index");
            if (!indexFile.HasValue) throw new Exception("index file doesn't exist");

            using (var reader = indexFile.Value.OpenReader())
            {
                return Read(reader);
            }
        }
        public async Task WriteAsync(IndexFile file)
        {
            var indexFile = await _fileManager.CreateOrReplaceRootFileAsync("index");
            if (!indexFile.HasValue) throw new Exception("index file doesn't exist");

            using (var writer = indexFile.Value.OpenWriter())
            {
                Write(writer, file);
            }
        }

        private static IndexFile Read(Stream input)
        {
            var header = input.ReadExactly(4);
            if (!header.Span.StartsWith(Header.Span)) throw new Exception("invalid format");

            var reader = new EndianBinaryReader(EndianBitConverter.Big, input);

            var version = reader.ReadUInt32();
            if (version < 2 || version > 4) throw new Exception("invalid format");

            var entryCount = reader.ReadUInt32();
            var entries = new List<IndexEntry>((int)entryCount);

            for (var i = 0; i < entryCount; i++)
            {
                entries.Add(ReadEntry(reader, version));
            }

            var extensions = new List<IndexExtension>();
            while (input.Length - input.Position > 20)
            {
                var extension = ReadExtension(reader);
                if (!extension.IsOptional)
                    throw new NotImplementedException("handle required extension");

                extensions.Add(extension);
            }

            var hash = reader.ReadBytes(20);
            // TODO verify hash

            return new IndexFile(version, entries, extensions);
        }
        private static void Write(Stream input, IndexFile file)
        {
            var signedStream = new SignedStream(input, new NullSignatureCipher(), new SHA1Digest());
            var writer = new EndianBinaryWriter(EndianBitConverter.Big, signedStream);

            writer.Write(Header.Span);
            writer.Write(file.Version);

            writer.Write(file.Entries.Count);
            foreach (var entry in file.Entries.OrderBy(x => x.Name))
            {
                WriteEntry(writer, file.Version, entry);
            }

            foreach (var extension in file.Extensions)
            {
                WriteExtension(writer, extension);
            }

            writer.Flush();
            var hash = signedStream.HashAlgorithm.Digest();
            input.Write(hash);
        }

        private static IndexEntry ReadEntry(EndianBinaryReader reader, uint version)
        {
            DateTime CreateDate(uint s, uint ns)
            {
                var ticksSinceEpoch = s * TimeSpan.TicksPerSecond + ns / 100;

                return Epoch.AddTicks(ticksSinceEpoch);
            }

            var created = CreateDate(reader.ReadUInt32(), reader.ReadUInt32());
            var modified = CreateDate(reader.ReadUInt32(), reader.ReadUInt32());

            var dev = reader.ReadUInt32();
            var ino = reader.ReadUInt32();

            var mode = reader.ReadUInt32();

            var uid = reader.ReadUInt32();
            var gid = reader.ReadUInt32();

            var size = reader.ReadUInt32();

            var hash = SequenceExtensions.Create(reader.BaseStream.ReadExactly(20));

            uint flags = reader.ReadUInt16();
            var extendedFlag = (flags & (1 << 14)) != 0;
            if (version < 3)
            {
                if (extendedFlag) throw new Exception("invalid format");
            }
            else
            {
                if (extendedFlag)
                {
                    flags |= (uint)(reader.ReadUInt16() << 16);
                }

            }

            var nameLength = flags & 0xfff;
            if (nameLength == 0xfff)
                throw new NotImplementedException("handle long file name");

            string name;
            if (version < 4)
            {
                var buffer = new List<byte>();

                var count = 0;
                for (; count < nameLength; count++)
                {
                    var b = reader.ReadByte();
                    if (b == 0) throw new Exception("invalid format");

                    buffer.Add(b);
                }

                if (!extendedFlag) count -= sizeof(ushort);

                while (count++ % 8 != 0)
                {
                    if (reader.ReadByte() != 0) throw new Exception("invalid format");
                }

                name = Encoding.UTF8.GetString(buffer.ToArray());
            }
            else
            {
                throw new NotImplementedException("handle prefix-compressed name");
            }

            return new IndexEntry(name, hash, size, flags, mode, created, modified, dev, ino, uid, gid);
        }

        private static void WriteEntry(EndianBinaryWriter writer, uint version, IndexEntry entry)
        {
            void WriteDate(DateTime datetime)
            {
                var ticksSinceEpoch = (datetime - Epoch).Ticks;

                var s = ticksSinceEpoch / TimeSpan.TicksPerSecond;
                var ns = (ticksSinceEpoch % TimeSpan.TicksPerSecond) * 100;

                writer.Write((uint)s);
                writer.Write((uint)ns);
            }

            WriteDate(entry.Created);
            WriteDate(entry.Modified);

            writer.Write(entry.DeviceId);
            writer.Write(entry.Inode);

            writer.Write(entry.Mode);

            writer.Write(entry.Uid);
            writer.Write(entry.Gid);

            writer.Write(entry.Size);

            if (entry.Hash.Length != 20) throw new Exception("invalid format");
            writer.Write(entry.Hash);

            var flags = entry.Flags;
            flags = (flags & ~0xfffu) | (uint)(entry.Name.Length >= 0xfff ? 0xfff : entry.Name.Length);

            byte[] buffer;
            if (version < 4)
            {
                buffer = Encoding.UTF8.GetBytes(entry.Name);
            }
            else
            {
                throw new NotImplementedException("handle prefix-compressed name");
            }

            writer.Write((ushort)(flags & 0xffff));
            var extendedFlag = (flags & (1 << 14)) != 0;
            if (version < 3)
            {
                if (extendedFlag) throw new Exception("invalid format");
            }
            else
            {
                if (extendedFlag)
                {
                    writer.Write((ushort)(flags >> 16));
                }
            }

            writer.Write(buffer);

            var paddingCount = 8 - (buffer.Length - (extendedFlag ? 0 : 2)) % 8;
            for (var i = 0; i < paddingCount; i++) writer.Write((byte)0);
        }

        private static IndexExtension ReadExtension(EndianBinaryReader reader)
        {
            var signature = reader.BaseStream.ReadExactly(4);
            var len = reader.ReadUInt32();

            var data = SequenceExtensions.Create(reader.BaseStream.ReadExactly((int)len));

            return new IndexExtension(signature, data);
        }
        private static void WriteExtension(EndianBinaryWriter writer, IndexExtension extension)
        {
            writer.Write(extension.Signature);
            writer.Write((uint)extension.Data.Length);
            writer.Write(extension.Data);
        }
    }
}
