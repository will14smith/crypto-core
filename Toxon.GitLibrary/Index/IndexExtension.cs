using System;
using System.Buffers;

namespace Toxon.GitLibrary.Index
{
    public class IndexExtension
    {
        public ReadOnlyMemory<byte> Signature { get; }
        public ReadOnlySequence<byte> Data { get; }

        public bool IsOptional => Signature.Span[0] >= 'A' && Signature.Span[0] <= 'Z';

        public IndexExtension(in ReadOnlyMemory<byte> signature, in ReadOnlySequence<byte> data)
        {
            if (signature.Length != 4) throw new Exception("invalid format");

            Signature = signature;
            Data = data;
        }
    }
}