using System;
using System.Buffers;
using Crypto.Utils;

namespace Toxon.GitLibrary.Objects
{
    public class ObjectRef
    {
        public static ObjectRef Zero { get; } = new ObjectRef(new byte[20]);
        
        public ReadOnlySequence<byte> Hash { get; }

        public ObjectRef(in ReadOnlyMemory<byte> hash)
        {
            Hash = SequenceExtensions.Create(hash);
        }
        public ObjectRef(in ReadOnlySequence<byte> hash)
        {
            Hash = hash;
        }
    }
}
