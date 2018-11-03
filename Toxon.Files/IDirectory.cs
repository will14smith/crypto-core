using Crypto.Utils;

namespace Toxon.Files
{
    public interface IDirectory
    {
        string Name { get; }
        string RootRelativePath { get; }

        Option<IDirectory> GetDirectory(string subPath, bool asRoot = false);
        Option<IDirectory> CreateDirectory(string subPath, bool asRoot = false);

        Option<IFile> GetFile(string subPath);
        Option<IFile> CreateFile(string subPath);
        bool RemoveFile(string subPath);
    }

    public static class DirectoryExtensions
    {
        public static Option<IDirectory> GetOrCreateDirectory(this IDirectory directory, string subPath)
        {
            var subDirectory = directory.GetDirectory(subPath);
            if (subDirectory.HasValue) return subDirectory;

            return directory.CreateDirectory(subPath);
        }

        public static Option<IFile> CreateOrReplaceFile(this IDirectory directory, string subPath)
        {
            directory.RemoveFile(subPath);
            return directory.CreateFile(subPath);
        }
    }
}