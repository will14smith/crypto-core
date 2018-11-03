using System.Collections.Generic;

namespace Toxon.GitLibrary.Index
{
    public class IndexFile
    {
        public uint Version { get; }
        public IReadOnlyList<IndexEntry> Entries { get; }
        public IReadOnlyCollection<IndexExtension> Extensions { get; }

        public IndexFile(uint version, IReadOnlyList<IndexEntry> entries, IReadOnlyCollection<IndexExtension> extensions)
        {
            Version = version;
            Entries = entries;
            Extensions = extensions;
        }
    }
}