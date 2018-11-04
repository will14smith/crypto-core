using System.Collections.Generic;
using Object = Toxon.GitLibrary.Objects.Object;

namespace Toxon.GitLibrary.Packs
{
    internal enum PackObjectType : byte
    {
        Commit = 1,
        Tree = 2,
        Blob = 3,
        Tag = 4,

        OfsDelta = 6,
        RefDelta = 7
    }

    public class PackFile
    {
        public IReadOnlyList<Object> Objects { get; }

        public PackFile(IReadOnlyList<Object> objects)
        {
            Objects = objects;
        }
    }
}
