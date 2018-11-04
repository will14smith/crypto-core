using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using Crypto.Utils;
using Toxon.GitLibrary.Objects;
using Object = Toxon.GitLibrary.Objects.Object;

namespace Toxon.GitLibrary.Packs
{
    public class PackFileResolver
    {
        public static Object ReadObject(Stream packReader, PackIndex index, ulong objectOffset)
        {
            var packObject = PackFileSerializer.ReadObject(packReader, objectOffset);

            var (objectType, objectContent) = ReadObject(packReader, index, packObject);

            return ObjectReader.Read(objectType, objectContent);
        }

        public static (ObjectType, ReadOnlySequence<byte>) ReadObject(Stream packReader, PackIndex index, PackObject packObject)
        {
            switch (packObject)
            {
                case PackObject.Standard standard:
                    switch (standard.Type)
                    {
                        case PackObjectType.Commit: return (ObjectType.Commit, standard.Content);
                        case PackObjectType.Tree: return (ObjectType.Tree, standard.Content);
                        case PackObjectType.Blob: return (ObjectType.Blob, standard.Content);
                        case PackObjectType.Tag: throw new NotImplementedException();

                        default: throw new ArgumentOutOfRangeException();
                    }

                case PackObject.OffsetDelta offsetDelta: return ApplyDelta(packReader, index, offsetDelta.Offset, offsetDelta.Instructions);

                case PackObject.RefDelta refDelta:
                    var offset = index.LookupOffset(refDelta.ObjectRef);
                    if (!offset.HasValue) throw new Exception("invalid object ref");
                    return ApplyDelta(packReader, index, offset.Value, refDelta.Instructions);

                default: throw new ArgumentOutOfRangeException(nameof(packObject));
            }
        }

        private static (ObjectType, ReadOnlySequence<byte>) ApplyDelta(Stream packReader, PackIndex index, ulong offset, IEnumerable<DeltaInstruction> instructions)
        {
            var savedOffset = packReader.Position;
            packReader.Position = 0;

            var basePackObject = PackFileSerializer.ReadObject(packReader, offset);
            var (baseObjectType, baseObjectContent) = ReadObject(packReader, index, basePackObject);

            var content = ApplyDeltaInstructions(instructions, baseObjectContent);

            packReader.Position = savedOffset;

            return (baseObjectType, content);
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
