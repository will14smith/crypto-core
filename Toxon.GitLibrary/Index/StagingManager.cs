using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;
using Crypto.Utils;
using Toxon.Files;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary.Index
{
    public class StagingManager
    {
        private readonly GitFileManager _fileManager;
        private readonly IndexManager _index;
        private readonly ObjectManager _objectManager;
        private readonly HeadManager _headManager;

        public StagingManager(GitFileManager fileManager, IndexManager index)
        {
            _fileManager = fileManager;
            _index = index;

            _objectManager = new ObjectManager(_fileManager);
            _headManager = new HeadManager(_fileManager);
        }

        public async Task<IReadOnlyCollection<IndexEntry>> ListAsync()
        {
            var entries = await _index.Raw.ListAsync();

            return entries;
        }

        public Task<CommitObject> CommitAsync(CommitObject.Actor author, CommitObject.Actor committer, string message)
        {
            return new StagingCommitter(_index, _objectManager, _headManager).CommitAsync(author, committer, message);
        }

        public Task BuildIndexAsync(ObjectRef commitRef = null)
        {
            return new IndexFileBuilder(new IndexFileSerializer(_fileManager), _objectManager, _headManager).BuildIndexAsync();
        }

        public async Task<IndexEntry> StageAsync(IFile file)
        {
            ReadOnlySequence<byte> content;
            using (var reader = file.OpenReader())
                content = reader.ReadAll();

            var objectRef = await _objectManager.WriteAsync(new BlobObject(content));
            var indexEntry = await _index.StageAsync(file, objectRef);

            return indexEntry;
        }

        public async Task RemoveAsync(string name)
        {
            await _index.RemoveAsync(name);
        }
    }
}