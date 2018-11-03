using System;
using System.Buffers;
using System.IO;
using System.Text;
using Crypto.Utils;

namespace Toxon.GitLibrary.Objects
{
    public static class ObjectReader
    {
        public static Object Read(ObjectRef hash, Stream input)
        {
            var inflatedInput = Zlib.Inflate(input);
            var (type, _, rawContent) = ReadHeader(inflatedInput);

            // TODO verify length?

            return Read(type, rawContent);
        }

        public static Object Read(ObjectType type, ReadOnlySequence<byte> rawContent)
        {
            switch (type)
            {
                case ObjectType.Blob: return new BlobObject(rawContent);
                case ObjectType.Commit: return CommitObject.Parse(rawContent);
                case ObjectType.Tree: return TreeObject.Parse(rawContent);

                default: throw new ArgumentOutOfRangeException();
            }
        }

        private static (ObjectType, uint, ReadOnlySequence<byte>) ReadHeader(in ReadOnlySequence<byte> input)
        {
            var encoding = Encoding.UTF8;

            var (type, remainingInput) = ReadType(input, encoding);

            if (encoding.GetString(remainingInput.Slice(0, 1)) != " ") throw new Exception("Invalid format");

            var headerTerminator = remainingInput.PositionOf((byte)0);
            if (headerTerminator == null) throw new Exception("Invalid format");

            var lengthSlice = remainingInput.Slice(1, headerTerminator.Value);
            if (!uint.TryParse(encoding.GetString(lengthSlice), out var length)) throw new Exception("Invalid format");

            var rawContent = remainingInput.Slice(headerTerminator.Value).Slice(1);

            return (type, length, rawContent);
        }

        private static (ObjectType type, ReadOnlySequence<byte> remainingInput) ReadType(ReadOnlySequence<byte> input, Encoding encoding)
        {
            switch (encoding.GetString(input.Slice(0, 1)))
            {
                case "b":
                    {
                        var typeStr = encoding.GetString(input.Slice(0, 4));
                        if (typeStr != "blob") throw new ArgumentOutOfRangeException();

                        return (ObjectType.Blob, input.Slice(4));
                    }
                case "c":
                    {
                        var typeStr = encoding.GetString(input.Slice(0, 6));
                        if (typeStr != "commit") throw new ArgumentOutOfRangeException();

                        return (ObjectType.Commit, input.Slice(6));
                    }
                case "t":
                    {
                        var typeStr = encoding.GetString(input.Slice(0, 4));
                        if (typeStr != "tree") throw new ArgumentOutOfRangeException();

                        return (ObjectType.Tree, input.Slice(4));
                    }

                default: throw new ArgumentOutOfRangeException();
            }
        }
    }
}
