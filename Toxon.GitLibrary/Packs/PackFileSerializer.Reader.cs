using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using Crypto.Utils;
using Crypto.Utils.IO;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary.Packs
{
    public partial class PackFileSerializer
    {
        public static PackFile Read(Stream input)
        {
            var reader = new EndianBinaryReader(EndianBitConverter.Big, input);
            VerifyHeader(reader);

            var objectCount = reader.ReadUInt32();

            var objects = new PackObject[objectCount];
            for (var i = 0; i < objectCount; i++)
            {
                objects[i] = ReadObject(reader);
            }

            var hash = input.ReadExactly(20);
            // TODO verify hash

            return new PackFile(objects);
        }

        public static PackObject ReadObject(Stream input, ulong objectOffset)
        {
            var reader = new EndianBinaryReader(EndianBitConverter.Big, input);
            VerifyHeader(reader);

            input.Seek((long) objectOffset, SeekOrigin.Begin);

            return ReadObject(reader);
        }

        private static void VerifyHeader(EndianBinaryReader reader)
        {
            if (!reader.BaseStream.CanSeek) throw new Exception("Stream must be seekable");

            var signature = reader.BaseStream.ReadExactly(Signature.Length);
            if (!signature.Span.StartsWith(Signature.Span)) throw new Exception("invalid format");

            var version = reader.ReadUInt32();
            if (version != 2) throw new Exception("unsupported version");
        }

        internal static PackObject ReadObject(EndianBinaryReader reader)
        {
            var objectOffset = reader.BaseStream.Position;
            var (type, length) = ReadTypeAndLength(reader);

            // TODO calculate crc while inflating

            switch (type)
            {
                case PackObjectType.Commit: 
                case PackObjectType.Tree:
                case PackObjectType.Blob: 
                case PackObjectType.Tag: return new PackObject.Standard(type, Zlib.Inflate(reader.BaseStream));

                case PackObjectType.OfsDelta: return ReadOfsDelta(reader, objectOffset);
                case PackObjectType.RefDelta: return ReadRefDelta(reader);

                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private static (PackObjectType type, ulong length) ReadTypeAndLength(EndianBinaryReader reader)
        {
            var typeLengthByte = reader.ReadByte();

            var type = (PackObjectType) ((typeLengthByte >> 4) & 0b111);
            var length = (ulong) (typeLengthByte & 0xf);

            var shift = 4;
            while ((typeLengthByte & 0x80) != 0)
            {
                typeLengthByte = reader.ReadByte();

                length += (ulong) ((typeLengthByte & 0x7f) << shift);
                shift += 7;
            }

            return (type, length);
        }

        private static PackObject ReadOfsDelta(EndianBinaryReader reader, long objectOffset)
        {
            var c = reader.ReadByte();
            long offset = c & 0x7fu;

            while ((c & 0x80) != 0)
            {
                offset += 1;
                c = reader.ReadByte();
                offset = (offset << 7) | (c & 0x7fu);
            }

            offset = objectOffset - offset;

            var content = Zlib.Inflate(reader.BaseStream);
            var (sourceSize, targetSize, instructions) = ReadDeltaInstructions(content);

            return new PackObject.OffsetDelta((ulong)offset, sourceSize, targetSize, instructions, content);
        }

        private static PackObject ReadRefDelta(EndianBinaryReader reader)
        {
            var baseObjectRef = new ObjectRef(reader.ReadBytes(20));

            var content = Zlib.Inflate(reader.BaseStream);
            var (sourceSize, targetSize, instructions) = ReadDeltaInstructions(content);

            return new PackObject.RefDelta(baseObjectRef, sourceSize, targetSize, instructions, content);
        }

        private static (ulong, ulong, IReadOnlyList<DeltaInstruction>) ReadDeltaInstructions(ReadOnlySequence<byte> inflatedContent)
        {
            // TODO :( remove ToArray
            var content = new ReadOnlyMemory<byte>(inflatedContent.ToArray());

            var instructions = new List<DeltaInstruction>();

            var offset = 0;

            var sourceSize = ReadDeltaSize(content, ref offset);
            var targetSize = ReadDeltaSize(content, ref offset);
            var totalSize = 0ul;
            
            while (offset < content.Length)
            {
                var op = content.Span[offset++];

                if ((op & 0x80) == 0)
                {
                    var length = op & 0x7f;
                    if (length == 0) throw new Exception("invalid format");

                    var data = content.Slice(offset, length);
                    offset += length;

                    totalSize += (uint)length;
                    instructions.Add(new DeltaInstruction.Add(data));
                }
                else
                {
                    uint instructionOffset = 0;
                    uint length = 0;

                    if ((op & 0x1) != 0) instructionOffset |= (uint) content.Span[offset++] << 0;
                    if ((op & 0x2) != 0) instructionOffset |= (uint) content.Span[offset++] << 8;
                    if ((op & 0x4) != 0) instructionOffset |= (uint) content.Span[offset++] << 16;
                    if ((op & 0x8) != 0) instructionOffset |= (uint) content.Span[offset++] << 24;

                    if ((op & 0x10) != 0) length |= (uint) content.Span[offset++] << 0;
                    if ((op & 0x20) != 0) length |= (uint) content.Span[offset++] << 8;
                    if ((op & 0x40) != 0) length |= (uint) content.Span[offset++] << 16;

                    if (length == 0)
                        length = 0x10000;

                    if (instructionOffset + length > sourceSize) throw new Exception("copy instruction would overflow");

                    totalSize += length;
                    instructions.Add(new DeltaInstruction.Copy(instructionOffset, length));
                }
            }

            if (targetSize != totalSize) throw new Exception("instructions do not fill the target");

            return (sourceSize, targetSize, instructions);
        }

        private static ulong ReadDeltaSize(in ReadOnlyMemory<byte> content, ref int offset)
        {
            byte b;

            var length = 0ul;
            var shift = 0;
            do
            {
                b = content.Span[offset++];

                length += (ulong) ((b & 0x7f) << shift);
                shift += 7;
            } while ((b & 0x80) != 0);

            return length;
        }
    }
}