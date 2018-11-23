using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using Crypto.Utils;
using Toxon.GitLibrary.Objects;
using Object = Toxon.GitLibrary.Objects.Object;

namespace Toxon.GitLibrary.Packs
{
    public delegate Option<ulong> PackIndexLookup(ObjectRef objectRef);

    public class PackFileResolver
    {
        public static Option<Object> ReadObject(Stream packReader, PackIndexLookup lookup, ulong objectOffset)
        {
            var packObject = PackFileSerializer.ReadObject(packReader, objectOffset);

            var objOpt = ReadObject(packReader, lookup, packObject);
            if (!objOpt.HasValue) return Option.None<Object>();

            var (objectType, objectContent) = objOpt.Value;

            var obj = ObjectReader.Read(objectType, objectContent);
            return Option.Some(obj);
        }

        public static Option<(ObjectType, ReadOnlySequence<byte>)> ReadObject(Stream packReader, PackIndexLookup lookup, PackObject packObject)
        {
            switch (packObject)
            {
                case PackObject.Standard standard:
                    switch (standard.Type)
                    {
                        case PackObjectType.Commit: return Option.Some((ObjectType.Commit, standard.Content));
                        case PackObjectType.Tree: return Option.Some((ObjectType.Tree, standard.Content));
                        case PackObjectType.Blob: return Option.Some((ObjectType.Blob, standard.Content));
                        case PackObjectType.Tag: throw new NotImplementedException();

                        default: throw new ArgumentOutOfRangeException();
                    }

                case PackObject.OffsetDelta offsetDelta:
                    return ApplyDelta(packReader, lookup, offsetDelta.Offset, offsetDelta.SourceSize, offsetDelta.TargetSize, offsetDelta.Instructions);

                case PackObject.RefDelta refDelta:
                    var offsetOpt = lookup(refDelta.ObjectRef);
                    return offsetOpt.SelectMany(offset => ApplyDelta(packReader, lookup, offset, refDelta.SourceSize, refDelta.TargetSize, refDelta.Instructions));

                default: throw new ArgumentOutOfRangeException(nameof(packObject));
            }
        }

        private static Option<(ObjectType, ReadOnlySequence<byte>)> ApplyDelta(Stream packReader, PackIndexLookup lookup, ulong offset, ulong sourceSize, ulong targetSize, IEnumerable<DeltaInstruction> instructions)
        {
            var savedOffset = packReader.Position;
            packReader.Position = 0;

            var basePackObject = PackFileSerializer.ReadObject(packReader, offset);
            var baseObjectOpt = ReadObject(packReader, lookup, basePackObject);
            if (!baseObjectOpt.HasValue) return Option.None<(ObjectType, ReadOnlySequence<byte>)>();
            var (baseObjectType, baseObjectContent) = baseObjectOpt.Value;

            if ((ulong)baseObjectContent.Length != sourceSize) throw new Exception("base object is incorrect length");

            var content = ApplyDeltaInstructions(instructions, baseObjectContent);
            if ((ulong)content.Length != targetSize) throw new Exception("content is incorrect length");

            packReader.Position = savedOffset;

            return Option.Some((baseObjectType, content));
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
