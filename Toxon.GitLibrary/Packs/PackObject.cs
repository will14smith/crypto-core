﻿using System.Buffers;
using System.Collections.Generic;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary.Packs
{
    public enum PackObjectType : byte
    {
        Commit = 1,
        Tree = 2,
        Blob = 3,
        Tag = 4,

        OfsDelta = 6,
        RefDelta = 7
    }

    public abstract class PackObject
    {
        protected PackObject(ReadOnlySequence<byte> content)
        {
            Content = content;
        }

        public abstract PackObjectType Type { get; }

        public ReadOnlySequence<byte> Content { get; }

        public class Standard : PackObject
        {
            public override PackObjectType Type { get; }

            public Standard(PackObjectType type, ReadOnlySequence<byte> content) : base(content)
            {
                Type = type;
            }
        }

        public class OffsetDelta : PackObject
        {
            public ulong Offset { get; }
            public ulong SourceSize { get; }
            public ulong TargetSize { get; }
            public IReadOnlyList<DeltaInstruction> Instructions { get; }
            public override PackObjectType Type => PackObjectType.OfsDelta;

            public OffsetDelta(ulong offset, ulong sourceSize, ulong targetSize, IReadOnlyList<DeltaInstruction> instructions, ReadOnlySequence<byte> content) : base(content)
            {
                Offset = offset;
                SourceSize = sourceSize;
                TargetSize = targetSize;
                Instructions = instructions;
            }
        }

        public class RefDelta : PackObject
        {
            public ObjectRef ObjectRef { get; }
            public ulong SourceSize { get; }
            public ulong TargetSize { get; }
            public IReadOnlyList<DeltaInstruction> Instructions { get; }
            public override PackObjectType Type => PackObjectType.RefDelta;

            public RefDelta(ObjectRef objectRef, ulong sourceSize, ulong targetSize, IReadOnlyList<DeltaInstruction> instructions, ReadOnlySequence<byte> content) : base(content)
            {
                ObjectRef = objectRef;
                SourceSize = sourceSize;
                TargetSize = targetSize;
                Instructions = instructions;
            }
        }
    }
}
