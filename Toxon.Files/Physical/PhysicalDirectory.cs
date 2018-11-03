using System.IO;
using Crypto.Utils;

namespace Toxon.Files.Physical
{
    public class PhysicalDirectory : IDirectory
    {
        private readonly string _rootPath;

        private PhysicalDirectory(string rootPath, string relativePath)
        {
            _rootPath = rootPath;
            RootRelativePath = relativePath;
        }

        public static PhysicalDirectory Open(string path)
        {
            if (!Directory.Exists(path)) throw new DirectoryNotFoundException();

            return new PhysicalDirectory(path, "");
        }

        public string Name => Path.GetDirectoryName(RootRelativePath);
        public string RootRelativePath { get; }

        public Option<IDirectory> GetDirectory(string subPath, bool asRoot = false)
        {
            // TODO prevent directory traversal
            var relativePath = Path.Combine(RootRelativePath, subPath);

            var path = Path.Combine(_rootPath, relativePath);
            if (!Directory.Exists(path)) return Option.None<IDirectory>();

            return GetPathInternal(asRoot, path, relativePath);
        }

        public Option<IDirectory> CreateDirectory(string subPath, bool asRoot = false)
        {
            // TODO prevent directory traversal
            var relativePath = Path.Combine(RootRelativePath, subPath);

            var path = Path.Combine(_rootPath, relativePath);
            if (Directory.Exists(path)) return Option.None<IDirectory>();

            Directory.CreateDirectory(path);

            return GetPathInternal(asRoot, path, relativePath);
        }

        private Option<IDirectory> GetPathInternal(bool asRoot, string path, string relativePath)
        {
            var physicalDirectory = asRoot ? new PhysicalDirectory(path, "") : new PhysicalDirectory(_rootPath, relativePath);
            return Option.Some<IDirectory>(physicalDirectory);
        }

        public Option<IFile> GetFile(string subPath)
        {
            // TODO prevent directory traversal
            var relativePath = Path.Combine(RootRelativePath, subPath.TrimEnd('\n'));

            var path = Path.Combine(_rootPath, relativePath);
            if (!File.Exists(path)) return Option.None<IFile>();

            return Option.Some<IFile>(new PhysicalFile(_rootPath, relativePath));
        }

        public Option<IFile> CreateFile(string subPath)
        {
            var relativePath = Path.Combine(RootRelativePath, subPath.TrimEnd('\n'));

            var path = Path.Combine(_rootPath, relativePath);
            if (File.Exists(path)) return Option.None<IFile>();

            File.Create(path).Close();

            return Option.Some<IFile>(new PhysicalFile(_rootPath, relativePath));
        }

        public bool RemoveFile(string subPath)
        {
            var path = Path.Combine(_rootPath, RootRelativePath, subPath.TrimEnd('\n'));

            if (!File.Exists(path)) return false;

            File.Delete(path);
            return true;
        }
    }
}
