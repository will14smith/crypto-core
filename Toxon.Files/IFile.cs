using System;
using System.IO;

namespace Toxon.Files
{
    public interface IFile
    {
        FileInfo Info { get; }

        Stream OpenReader();
        Stream OpenWriter();
    }

    public struct FileInfo
    {
        public FileInfo(string rootRelativePath, uint size, DateTime created, DateTime modified)
        {
            RootRelativePath = rootRelativePath;
            Size = size;
            Created = created;
            Modified = modified;
        }

        public string RootRelativePath { get; }
        public uint Size { get; }
        public DateTime Created { get; }
        public DateTime Modified { get; }

        public string Name => Path.GetFileName(RootRelativePath);
    }
}
