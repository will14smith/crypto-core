using System.Buffers;

namespace Toxon.GitLibrary.Objects
{
    public abstract class Object
    {
        public abstract ObjectType Type { get; }
        public abstract ReadOnlySequence<byte> ToBuffer();
    }
}
