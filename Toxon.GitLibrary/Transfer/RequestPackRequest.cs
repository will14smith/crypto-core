using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Crypto.Utils;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary.Transfer
{
    public class RequestPackRequest
    {
        private static readonly ReadOnlyMemory<byte> WantHeader = Encoding.UTF8.GetBytes("want ");
        private static readonly ReadOnlyMemory<byte> HaveHeader = Encoding.UTF8.GetBytes("have ");
        private static readonly ReadOnlyMemory<byte> StandardLengthHeader = Encoding.UTF8.GetBytes("0032");
        private static readonly ReadOnlyMemory<byte> NewLine = Encoding.UTF8.GetBytes("\n");
        private static readonly ReadOnlyMemory<byte> Done = Encoding.UTF8.GetBytes("0009done\n");

        public IReadOnlyCollection<string> Capabilities { get; }

        public IReadOnlyCollection<ObjectRef> Want { get; }
        public IReadOnlyCollection<ObjectRef> Have { get; }

        public RequestPackRequest(IReadOnlyCollection<string> capabilities, IReadOnlyCollection<ObjectRef> want, IReadOnlyCollection<ObjectRef> have)
        {
            if (want.Count == 0)
            {
                throw new ArgumentException("Must want at least 1 object");
            }

            Capabilities = capabilities;

            Want = want;
            Have = have;
        }

        public ReadOnlySequence<byte> AsBuffer()
        {
            var seq = new List<ReadOnlyMemory<byte>>();

            var first = true;
            foreach (var want in Want)
            {
                if (first)
                {
                    first = false;

                    if (Capabilities.Count > 0)
                    {
                        throw new NotImplementedException("list capabilities");
                    }
                }

                seq.Add(StandardLengthHeader);
                seq.Add(WantHeader);
                seq.Add(HexConverter.ToHexBytes(want.Hash));
                seq.Add(NewLine);
            }
            foreach (var have in Have)
            {
                seq.Add(StandardLengthHeader);
                seq.Add(HaveHeader);
                seq.Add(HexConverter.ToHexBytes(have.Hash));
                seq.Add(NewLine);
            }

            seq.Add(TransferRecord.Flush);
            seq.Add(Done);

            return seq.ToSequence();
        }
    }
}