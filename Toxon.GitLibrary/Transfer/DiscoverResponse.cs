using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Crypto.Utils;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary.Transfer
{
    public class DiscoverResponse
    {
        private static readonly ReadOnlyMemory<byte> Header = Encoding.UTF8.GetBytes("# service=git-receive-pack\n");
        private static readonly ReadOnlyMemory<byte> Space = Encoding.UTF8.GetBytes(" ");
        private static readonly ReadOnlyMemory<byte> ZeroId = new byte[20];

        private readonly Dictionary<string, ObjectRef> _branches = new Dictionary<string, ObjectRef>();

        public IReadOnlyCollection<string> Capabilities { get; private set; }
        public IReadOnlyDictionary<string, ObjectRef> Branches => _branches;

        public static DiscoverResponse Parse(ReadOnlySequence<byte> content)
        {
            ReadOnlySequence<byte> header;
            (header, content) = TransferRecord.Read(content);
            if (header.Length != Header.Length || !header.StartsWith(Header.Span))
            {
                throw new Exception("invalid format");
            }
            content = TransferRecord.ReadFlush(content);

            var response = new DiscoverResponse();

            ReadOnlySequence<byte> line;

            (line, content) = TransferRecord.Read(content);
            var shouldContinue = ReadCapabilities(line, response);

            while (shouldContinue && content.Length > 4)
            {
                (line, content) = TransferRecord.Read(content);
                ReadRecord(line, response);
            }

            content = TransferRecord.ReadFlush(content);
            if (content.Length != 0)
            {
                throw new Exception("invalid format");
            }

            return response;
        }

        private static bool ReadCapabilities(ReadOnlySequence<byte> line, DiscoverResponse response)
        {
            // Parse line
            ReadOnlySequence<byte> idBuffer;
            (idBuffer, line) = line.Split(40);

            if (!line.StartsWith(Space.Span))
            {
                throw new Exception("invalid format");
            }
            line = line.Slice(1);

            ReadOnlySequence<byte> nameBuffer;
            (nameBuffer, line) = line.SplitFirst((byte)0);

            ReadOnlySequence<byte> capabilitiesBuffer;
            (capabilitiesBuffer, line) = line.SplitFirst((byte)'\n');

            if (line.Length != 0)
            {
                throw new Exception("invalid format");
            }

            // Handle data
            var id = HexConverter.FromHex(idBuffer);
            var name = Encoding.UTF8.GetString(nameBuffer);

            var isZeroId = id.StartsWith(ZeroId.Span);
            if (isZeroId)
            {
                if (name != "capabilities^{}")
                {
                    throw new Exception("invalid format");
                }
            }
            else
            {
                response._branches.Add(name, new ObjectRef(id));
            }

            response.Capabilities = Encoding.UTF8.GetString(capabilitiesBuffer).Split(' ');

            return !isZeroId;
        }

        private static void ReadRecord(ReadOnlySequence<byte> line, DiscoverResponse response)
        {
            // Parse line
            ReadOnlySequence<byte> idBuffer;
            (idBuffer, line) = line.Split(40);

            if (!line.StartsWith(Space.Span))
            {
                throw new Exception("invalid format");
            }
            line = line.Slice(1);

            ReadOnlySequence<byte> nameBuffer;
            (nameBuffer, line) = line.SplitFirst((byte)'\n');

            if (line.Length != 0)
            {
                throw new Exception("invalid format");
            }

            // Handle data
            var name = Encoding.UTF8.GetString(nameBuffer);
            var id = HexConverter.FromHex(idBuffer);

            if (name.EndsWith("^{}"))
            {
                throw new NotImplementedException();
            }

            response._branches.Add(name, new ObjectRef(id));
        }
    }
}