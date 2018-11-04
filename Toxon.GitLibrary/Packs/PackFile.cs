using System.Collections.Generic;

namespace Toxon.GitLibrary.Packs
{
    public class PackFile
    {
        public IReadOnlyList<PackObject> Objects { get; }

        public PackFile(IReadOnlyList<PackObject> objects)
        {
            Objects = objects;
        }
    }
}
