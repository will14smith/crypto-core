using System;

namespace Toxon.GitLibrary.Packs
{
    public abstract class DeltaInstruction
    {
        public class Add : DeltaInstruction
        {
            public ReadOnlyMemory<byte> Data { get; }

            public Add(in ReadOnlyMemory<byte> data)
            {
                Data = data;
            }
        }

        public class Copy : DeltaInstruction
        {
            public uint Offset { get; }
            public uint Length { get; }

            public Copy(uint offset, uint length)
            {
                Offset = offset;
                Length = length;
            }
        }
    }
}