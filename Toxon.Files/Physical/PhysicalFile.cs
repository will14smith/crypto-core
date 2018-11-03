using System.IO;

namespace Toxon.Files.Physical
{
    public class PhysicalFile : IFile
    {
        private readonly string _rootPath;
        private readonly string _relativePath;

        internal PhysicalFile(string rootPath, string relativePath)
        {
            _rootPath = rootPath;
            _relativePath = relativePath;
        }

        public FileInfo Info => GetInfo();

        private FileInfo GetInfo()
        {
            var path = Path.Combine(_rootPath, _relativePath);
            var length = GetLength(path);
            var created = File.GetCreationTimeUtc(path);
            var modified = File.GetLastWriteTimeUtc(path);

            return new FileInfo(_relativePath, length, created, modified);
        }

        private static uint GetLength(string path)
        {
            using (var stream = File.OpenRead(path))
            {
                return (uint)stream.Length;
            }
        }

        public Stream OpenReader()
        {
            var path = Path.Combine(_rootPath, _relativePath);
            var reader = File.OpenRead(path);

            return reader;
        }

        public Stream OpenWriter()
        {
            var path = Path.Combine(_rootPath, _relativePath);
            var writer = File.OpenWrite(path);

            return writer;
        }
    }
}