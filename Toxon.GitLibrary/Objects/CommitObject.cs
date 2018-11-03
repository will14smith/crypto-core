using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Crypto.Utils;

namespace Toxon.GitLibrary.Objects
{
    public class CommitObject : Object
    {
        private static class Constants
        {
            public static readonly ReadOnlyMemory<byte> Tree = Encoding.UTF8.GetBytes("tree ").AsMemory();
            public static readonly ReadOnlyMemory<byte> Parent = Encoding.UTF8.GetBytes("parent ").AsMemory();
            public static readonly ReadOnlyMemory<byte> Author = Encoding.UTF8.GetBytes("author ").AsMemory();
            public static readonly ReadOnlyMemory<byte> Committer = Encoding.UTF8.GetBytes("committer ").AsMemory();

            public static readonly ReadOnlyMemory<byte> EmailOpen = Encoding.UTF8.GetBytes(" <").AsMemory();
            public static readonly ReadOnlyMemory<byte> EmailClose = Encoding.UTF8.GetBytes("> ").AsMemory();
            public static readonly ReadOnlyMemory<byte> Space = Encoding.UTF8.GetBytes(" ").AsMemory();
            public static readonly ReadOnlyMemory<byte> NewLine = Encoding.UTF8.GetBytes("\n").AsMemory();

            public static readonly DateTime Epoch = new DateTime(1970, 1, 1);
        }

        public CommitObject(ObjectRef tree, IReadOnlyList<ObjectRef> parents, Actor author, Actor committer, string message)
        {
            Tree = tree;
            Parents = parents;

            Author = author;
            Committer = committer;
            Message = message;
        }

        public override ObjectType Type => ObjectType.Commit;

        public ObjectRef Tree { get; }
        public IReadOnlyList<ObjectRef> Parents { get; }

        public Actor Author { get; }
        public Actor Committer { get; }
        public string Message { get; }

        public override ReadOnlySequence<byte> ToBuffer()
        {
            var tree = SequenceExtensions.Create(Constants.Tree, HexConverter.ToHexBytes(Tree.Hash), Constants.NewLine);
            var parents = Parents.Select(x => SequenceExtensions.Create(Constants.Parent, HexConverter.ToHexBytes(x.Hash), Constants.NewLine)).ToArray();
            var author = Author.ToBuffer(Constants.Author);
            var committer = Committer.ToBuffer(Constants.Committer);
            var message = SequenceExtensions.Create(Constants.NewLine, Encoding.UTF8.GetBytes(Message));

            var content = tree.Concat(parents).Concat(author, committer, message);

            var prefix = Encoding.UTF8.GetBytes("commit " + content.Length);
            var header = SequenceExtensions.Create<byte>(prefix, new byte[] { 0 });

            return header.Concat(content);
        }

        public static CommitObject Parse(ReadOnlySequence<byte> rawContent)
        {
            // tree<space>string-hash\n
            if (!rawContent.StartsWith(Constants.Tree.Span)) throw new Exception("Invalid format");
            rawContent = rawContent.Slice(Constants.Tree.Length);
            var treeTerminator = rawContent.PositionOf(Constants.NewLine.Span);
            if (!treeTerminator.HasValue) throw new Exception("Invalid format");
            var treeSlice = rawContent.Slice(0, treeTerminator.Value);
            if (treeSlice.Length != 40) throw new Exception("Invalid format");
            var tree = new ObjectRef(HexConverter.FromHex(treeSlice));
            rawContent = rawContent.Slice(41);

            var parents = new List<ObjectRef>();
            while (rawContent.StartsWith(Constants.Parent.Span))
            {
                // (parent<space>string-hash\n)*
                rawContent = rawContent.Slice(Constants.Parent.Length);
                var parentTerminator = rawContent.PositionOf(Constants.NewLine.Span);
                if (!parentTerminator.HasValue) throw new Exception("Invalid format");
                var parentSlice = rawContent.Slice(0, parentTerminator.Value);
                if (parentSlice.Length != 40) throw new Exception("Invalid format");
                var parent = HexConverter.FromHex(parentSlice);
                rawContent = rawContent.Slice(41);

                parents.Add(new ObjectRef(parent));
            }

            // author<space>string-name<space><angle-open>string-email<angle-close><space><string-date-seconds><space><string-date-timezone>\n
            Actor author;
            (author, rawContent) = ReadActor(Constants.Author, rawContent);

            // committer<space>string-name<space><angle-open>string-email<angle-close><space><string-date-seconds><space><string-date-timezone>\n
            Actor committer;
            (committer, rawContent) = ReadActor(Constants.Committer, rawContent);

            // \n
            if (!rawContent.StartsWith(Constants.NewLine.Span)) throw new Exception("Invalid format");
            rawContent = rawContent.Slice(Constants.NewLine.Length);

            // string-commit-message
            var message = Encoding.UTF8.GetString(rawContent);

            return new CommitObject(tree, parents, author, committer, message);
        }

        private static (Actor actor, ReadOnlySequence<byte> rawContent) ReadActor(in ReadOnlyMemory<byte> header, ReadOnlySequence<byte> rawContent)
        {
            // <header><space>string-name<space><angle-open>string-email<angle-close><space><string-date-seconds><space><string-date-timezone>\n

            if (!rawContent.StartsWith(header.Span)) throw new Exception("Invalid format");
            rawContent = rawContent.Slice(header.Length);

            var nameTerminator = rawContent.PositionOf(Constants.EmailOpen.Span);
            if (!nameTerminator.HasValue) throw new Exception("Invalid format");
            var nameSlice = rawContent.Slice(0, nameTerminator.Value);
            var name = Encoding.UTF8.GetString(nameSlice);
            rawContent = rawContent.Slice(nameTerminator.Value).Slice(Constants.EmailOpen.Length);

            var emailTerminator = rawContent.PositionOf(Constants.EmailClose.Span);
            if (!emailTerminator.HasValue) throw new Exception("Invalid format");
            var emailSlice = rawContent.Slice(0, emailTerminator.Value);
            var email = Encoding.UTF8.GetString(emailSlice);
            rawContent = rawContent.Slice(emailTerminator.Value).Slice(Constants.EmailClose.Length);

            var timestampTerminator = rawContent.PositionOf(Constants.Space.Span);
            if (!timestampTerminator.HasValue) throw new Exception("Invalid format");
            var timestampSlice = rawContent.Slice(0, timestampTerminator.Value);
            var timestamp = ulong.Parse(Encoding.UTF8.GetString(timestampSlice));
            var baseDateTime = Constants.Epoch.AddSeconds(timestamp);
            rawContent = rawContent.Slice(timestampTerminator.Value).Slice(1);

            var utcOffsetTerminator = rawContent.PositionOf(Constants.NewLine.Span);
            if (!utcOffsetTerminator.HasValue) throw new Exception("Invalid format");
            var utcOffsetSlice = rawContent.Slice(0, utcOffsetTerminator.Value);
            var minuteSplitPoint = utcOffsetSlice.Length - 2;
            var hoursOffset = ushort.Parse(Encoding.UTF8.GetString(utcOffsetSlice.Slice(0, minuteSplitPoint)));
            var minutesOffset = ushort.Parse(Encoding.UTF8.GetString(utcOffsetSlice.Slice(minuteSplitPoint)));
            var offset = TimeSpan.FromHours(hoursOffset) + TimeSpan.FromMinutes(minutesOffset);
            rawContent = rawContent.Slice(utcOffsetTerminator.Value).Slice(1);

            var dateTime = new DateTimeOffset(baseDateTime, offset);

            var actor = new Actor(name, email, dateTime);
            return (actor, rawContent);
        }

        public override string ToString()
        {
            var part1 = $"commit - tree {HexConverter.ToHex(Tree.Hash.Slice(0, 4))} parents {string.Join(", ", Parents.Select(x => HexConverter.ToHex(x.Hash.Slice(0, 4))))}";
            var part2 = $"author {Author}\ncommitter {Committer}";

            return part1 + "\n" + part2 + "\n\n" + Message + "\n\n";
        }

        public class Actor
        {
            public Actor(string name, string email, DateTimeOffset timestamp)
            {
                Name = name;
                Email = email;

                Timestamp = timestamp;
            }

            public string Name { get; }
            public string Email { get; }

            public DateTimeOffset Timestamp { get; }

            public override string ToString()
            {
                return $"{Name} <{Email}> {Timestamp}";
            }

            public ReadOnlySequence<byte> ToBuffer(in ReadOnlyMemory<byte> header)
            {
                var encoding = Encoding.UTF8;

                var name = encoding.GetBytes(Name);
                var email = encoding.GetBytes(Email);
                var seconds = encoding.GetBytes(((int)(Timestamp.DateTime - Constants.Epoch).TotalSeconds).ToString());
                var timezone = encoding.GetBytes(Timestamp.Offset.Hours.ToString("+00") + Timestamp.Offset.Minutes.ToString("D2"));

                return SequenceExtensions.Create(header, name, Constants.EmailOpen, email, Constants.EmailClose, seconds, Constants.Space, timezone, Constants.NewLine);
            }
        }
    }
}