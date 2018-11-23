using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Crypto.Utils;

namespace Toxon.GitLibrary.Objects
{
    public class TreeObject : Object
    {
        public override ObjectType Type => ObjectType.Tree;

        public IReadOnlyDictionary<string, Entry> Entries { get; }

        public TreeObject(IReadOnlyDictionary<string, Entry> entries)
        {
            Entries = entries;
        }

        public override ReadOnlySequence<byte> ToBuffer()
        {
            var entries = Entries.Select(x => x.Value.ToBuffer()).ToArray();

            var prefix = Encoding.UTF8.GetBytes("tree " + entries.Sum(x => x.Length));
            var header = SequenceExtensions.Create<byte>(prefix, new byte[] { 0 });

            return header.Concat(entries);
        }

        public static TreeObject Parse(ReadOnlySequence<byte> rawContent)
        {
            var encoding = Encoding.UTF8;
            var entries = new Dictionary<string, Entry>();

            // octal-mode<space>string-path<null>binary-hash
            while (rawContent.Length > 0)
            {
                var octalModeTerminator = rawContent.PositionOf((byte)' ');
                if (!octalModeTerminator.HasValue) throw new Exception("Invalid format");

                var octalModeSlice = rawContent.Slice(0, octalModeTerminator.Value);
                var mode = ParseOctalMode(octalModeSlice);

                rawContent = rawContent.Slice(octalModeTerminator.Value);

                var pathTerminator = rawContent.PositionOf((byte)0);
                if (!pathTerminator.HasValue) throw new Exception("Invalid format");

                var pathSlice = rawContent.Slice(1, pathTerminator.Value);
                var path = encoding.GetString(pathSlice);

                rawContent = rawContent.Slice(pathTerminator.Value);

                var objectHash = new ObjectRef(rawContent.Slice(1, 20));

                rawContent = rawContent.Slice(21);

                entries.Add(path, new Entry(mode, path, objectHash));
            }

            return new TreeObject(entries);
        }

        internal static ReadOnlySequence<byte> FormatOctalMode(ushort mode)
        {
            var buffer = new byte[6];
            var start = 0;

            for (var i = 0; i < 6; i++)
            {
                var n = (mode >> (3 * (5 - i))) & 7;
                var d = (byte)('0' + n);

                if (n == 0 && start == i) start++;

                buffer[i] = d;
            }

            return SequenceExtensions.Create<byte>(buffer).Slice(start);
        }
        private static ushort ParseOctalMode(ReadOnlySequence<byte> octalMode)
        {
            ushort result = 0;
            foreach (var memory in octalMode)
            {
                foreach (var x in memory.Span)
                {
                    if (x < (byte)'0' || x > (byte)'7') throw new Exception("Invalid format");

                    var n = x - (byte)'0';

                    result = (ushort)((result * 8u) + n);
                }
            }

            return result;
        }

        public class Entry
        {
            public Entry(ushort mode, string path, in ObjectRef objectHash)
            {
                Mode = mode;
                Path = path;
                ObjectHash = objectHash;
            }

            public ushort Mode { get; }
            public string Path { get; }
            public ObjectRef ObjectHash { get; }

            public ReadOnlySequence<byte> ToBuffer()
            {
                var mode = FormatOctalMode(Mode);
                var path = Encoding.UTF8.GetBytes(Path);

                var middle = SequenceExtensions.Create<byte>(new[] { (byte)' ' }, path, new byte[] { 0 });

                return mode.Concat(middle, ObjectHash.Hash);
            }
        }
    }
}