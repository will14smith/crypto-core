using System;
using System.Threading.Tasks;
using Crypto.Utils;
using Toxon.Files;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary
{
    public class GitFileManager
    {
        private readonly IDirectory _repositoryFolder;

        public GitFileManager(IDirectory repositoryFolder)
        {
            _repositoryFolder = repositoryFolder;
        }

        public Task<Option<IFile>> GetObjectAsync(ObjectRef objectRef)
        {
            var hashStart = objectRef.Hash.Slice(0, 1);
            var hashEnd = objectRef.Hash.Slice(1);

            var folderPath = HexConverter.ToHex(hashStart);
            var fileName = HexConverter.ToHex(hashEnd);

            var objectsFolder = _repositoryFolder.GetDirectory("objects");
            if (!objectsFolder.HasValue) throw new Exception("invalid repository");

            var folder = objectsFolder.Value.GetDirectory(folderPath);
            var file = folder.SelectMany(x => x.GetFile(fileName));

            return Task.FromResult(file);
        }

        public Task<Option<IFile>> CreateObjectAsync(ObjectRef objectRef)
        {
            var hashStart = objectRef.Hash.Slice(0, 1);
            var hashEnd = objectRef.Hash.Slice(1);

            var folderPath = HexConverter.ToHex(hashStart);
            var fileName = HexConverter.ToHex(hashEnd);

            var objectsFolder = _repositoryFolder.GetDirectory("objects");
            if (!objectsFolder.HasValue) throw new Exception("invalid repository");

            var folder = objectsFolder.Value.GetOrCreateDirectory(folderPath);
            var file = folder.SelectMany(x => x.CreateFile(fileName));

            return Task.FromResult(file);
        }

        public Task<Option<IFile>> GetRefAsync(string path)
        {
            // TODO verify path is in <root>/refs/
            var file = _repositoryFolder.GetFile(path);

            return Task.FromResult(file);
        }
        public Task<Option<IFile>> CreateOrReplaceRefAsync(string path)
        {
            // TODO verify path is in <root>/refs/
            var file = _repositoryFolder.CreateOrReplaceFile(path);

            return Task.FromResult(file);
        }

        public Task<Option<IFile>> GetRootFileAsync(string path)
        {
            // TODO verify file is directly in <root>/
            var file = _repositoryFolder.GetFile(path);

            return Task.FromResult(file);
        }
        public Task<Option<IFile>> CreateOrReplaceRootFileAsync(string path)
        {
            var file = _repositoryFolder.CreateOrReplaceFile(path);

            return Task.FromResult(file);
        }
    }
}
