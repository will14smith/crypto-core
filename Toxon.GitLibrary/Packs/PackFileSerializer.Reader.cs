using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using Crypto.Utils;
using Crypto.Utils.IO;
using Toxon.GitLibrary.Objects;
using Object = Toxon.GitLibrary.Objects.Object;

namespace Toxon.GitLibrary.Packs
{
    public partial class PackFileSerializer
    {
        public static PackFile Read(Stream input, PackIndex index)
        {
            var reader = new EndianBinaryReader(EndianBitConverter.Big, input);
            VerifyHeader(reader);

            var objectCount = reader.ReadUInt32();

            var objects = new Object[objectCount];
            for (var i = 0; i < objectCount; i++)
            {
                var (type, content) = ReadObject(reader, index);

                objects[i] = ObjectReader.Read(type, content);
            }

            var hash = input.ReadExactly(20);
            // TODO verify hash

            return new PackFile(objects);
        }

        public static Object ReadObject(Stream input, PackIndex index, ulong objectOffset)
        {
            var reader = new EndianBinaryReader(EndianBitConverter.Big, input);
            VerifyHeader(reader);

            input.Seek((long) objectOffset, SeekOrigin.Begin);
            var (type, content) = ReadObject(reader, index);

            return ObjectReader.Read(type, content);
        }

        private static void VerifyHeader(EndianBinaryReader reader)
        {
            if (!reader.BaseStream.CanSeek) throw new Exception("Stream must be seekable");

            var signature = reader.BaseStream.ReadExactly(Signature.Length);
            if (!signature.Span.StartsWith(Signature.Span)) throw new Exception("invalid format");

            var version = reader.ReadUInt32();
            if (version != 2) throw new Exception("unsupported version");
        }

        private static (ObjectType, ReadOnlySequence<byte>) ReadObject(EndianBinaryReader reader, PackIndex index)
        {
            var objectOffset = reader.BaseStream.Position;
            var (type, length) = ReadTypeAndLength(reader);

            switch (type)
            {
                case PackObjectType.Commit: return (ObjectType.Commit, Zlib.Inflate(reader.BaseStream));
                case PackObjectType.Tree: return (ObjectType.Tree, Zlib.Inflate(reader.BaseStream));
                case PackObjectType.Blob: return (ObjectType.Blob, Zlib.Inflate(reader.BaseStream));
                case PackObjectType.Tag: throw new NotImplementedException();

                case PackObjectType.OfsDelta: return ReadOfsDelta(reader, index, objectOffset);
                case PackObjectType.RefDelta: return ReadRefDelta(reader, index);

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

        private static (ObjectType, ReadOnlySequence<byte>) ReadOfsDelta(EndianBinaryReader reader, PackIndex index, long objectOffset)
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

            var (sourceSize, targetSize, instructions) = ReadDeltaInstructions(reader);

            return ApplyDelta(reader, index, offset, instructions);
        }

        private static (ObjectType, ReadOnlySequence<byte>) ReadRefDelta(EndianBinaryReader reader, PackIndex index)
        {
            var baseObjectRef = new ObjectRef(reader.ReadBytes(20));
            var offset = index.LookupOffset(baseObjectRef);
            if (!offset.HasValue) throw new Exception("object ref is not in same pack file");

            var (sourceSize, targetSize, instructions) = ReadDeltaInstructions(reader);

            return ApplyDelta(reader, index, (long) offset.Value, instructions);
        }

        private static (ulong, ulong, IReadOnlyList<DeltaInstruction>) ReadDeltaInstructions(EndianBinaryReader reader)
        {
            var inflatedContent = Zlib.Inflate(reader.BaseStream);
            // TODO :( remove ToArray
            var content = new ReadOnlyMemory<byte>(inflatedContent.ToArray());

            var instructions = new List<DeltaInstruction>();

            var offset = 0;

            var sourceSize = ReadDeltaSize(content, ref offset);
            var targetSize = ReadDeltaSize(content, ref offset);

            while (offset < content.Length)
            {
                var op = content.Span[offset++];

                if ((op & 0x80) == 0)
                {
                    var length = op & 0x7f;
                    if (length == 0) throw new Exception("invalid format");

                    var data = content.Slice(offset, length);
                    offset += length;

                    instructions.Add(new DeltaInstruction.Add(data));
                }
                else
                {
                    uint instructionOffset = 0;
                    uint instructionLength = 0;

                    if ((op & 0x1) != 0) instructionOffset |= (uint) content.Span[offset++] << 0;
                    if ((op & 0x2) != 0) instructionOffset |= (uint) content.Span[offset++] << 8;
                    if ((op & 0x4) != 0) instructionOffset |= (uint) content.Span[offset++] << 16;
                    if ((op & 0x8) != 0) instructionOffset |= (uint) content.Span[offset++] << 24;

                    if ((op & 0x10) != 0) instructionLength |= (uint) content.Span[offset++] << 0;
                    if ((op & 0x20) != 0) instructionLength |= (uint) content.Span[offset++] << 8;
                    if ((op & 0x40) != 0) instructionLength |= (uint) content.Span[offset++] << 16;

                    instructions.Add(new DeltaInstruction.Copy(instructionOffset, instructionLength));
                }
            }

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

        private static (ObjectType, ReadOnlySequence<byte>) ApplyDelta(EndianBinaryReader reader, PackIndex index, long offset, IEnumerable<DeltaInstruction> instructions)
        {
            var stream = reader.BaseStream;
            var savedOffset = stream.Position;
            stream.Position = offset;

            var (baseType, baseContent) = ReadObject(reader, index);
            var content = ApplyDeltaInstructions(instructions, baseContent);

            stream.Position = savedOffset;

            return (baseType, content);
        }

        private static ReadOnlySequence<byte> ApplyDeltaInstructions(IEnumerable<DeltaInstruction> instructions, in ReadOnlySequence<byte> baseContent)
        {
            var output = new List<ReadOnlyMemory<byte>>();

            foreach (var instruction in instructions)
            {
                switch (instruction)
                {
                    case DeltaInstruction.Add add:
                        output.Add(add.Data);
                        break;

                    case DeltaInstruction.Copy copy:
                        var content = baseContent.Slice(copy.Offset, copy.Length);
                        output.AddRange(content);
                        break;

                    default: throw new ArgumentOutOfRangeException(nameof(instruction));
                }
            }

            return output.ToSequence();
        }
    }
}