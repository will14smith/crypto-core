using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Crypto.Utils;
using Toxon.Files;
using Toxon.GitLibrary.Index;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary
{
    public class GitRepository
    {
        private readonly GitFileManager _fileManager;

        internal GitRepository(IDirectory repositoryFolder)
        {
            _fileManager = new GitFileManager(repositoryFolder);
        }

        private IndexFileManager IndexFile => new IndexFileManager(_fileManager);
        private IndexManager Index => new IndexManager(IndexFile);
        public StagingManager Staging => new StagingManager(_fileManager, Index);

        public async Task<IReadOnlyCollection<CommitObject>> GetParentCommitsAsync(ObjectRef commitRef = null)
        {
            if (commitRef == null)
                commitRef = await GetHeadAsync();
            var commit = (CommitObject)await _fileManager.ReadObjectAsync(commitRef);

            var commits = new List<CommitObject>();
            while (true)
            {
                commits.Add(commit);

                var parentRef = commit.Parents.SingleOrDefault();
                if (parentRef == null) break;

                commit = (CommitObject)await _fileManager.ReadObjectAsync(parentRef);
            }

            return commits;
        }

        public async Task<IReadOnlyCollection<FileEntry>> GetFilesAsync(ObjectRef commitRef = null)
        {
            if (commitRef == null)
                commitRef = await GetHeadAsync();
            var commit = (CommitObject)await _fileManager.ReadObjectAsync(commitRef);

            var tree = (TreeObject)await _fileManager.ReadObjectAsync(commit.Tree);
            var walker = new TreeWalker(_fileManager);

            return await walker.WalkAsync(commit.Tree, tree);
        }


        private async Task<ObjectRef> GetHeadAsync()
        {
            var headManager = new HeadManager(_fileManager);
            return await headManager.ReadAsync();
        }
        private async Task SetHeadAsync(ObjectRef objectRef)
        {
            var headManager = new HeadManager(_fileManager);
            await headManager.WriterAsync(objectRef);
        }

        public async Task AddFileAsync(string path, ReadOnlySequence<byte> content, ObjectRef commitRef = null)
        {
            if (commitRef == null)
                commitRef = await GetHeadAsync();
            var commit = (CommitObject)await _fileManager.ReadObjectAsync(commitRef);

            var rootTree = (TreeObject)await _fileManager.ReadObjectAsync(commit.Tree);
            var walker = new TreeWalker(_fileManager);

            var directoryPath = Path.GetDirectoryName(path);
            var tree = await walker.FindOrCreateTreeAsync(directoryPath, rootTree);

            var fileName = Path.GetFileName(path);
            if (tree.Entries.ContainsKey(fileName)) throw new Exception("file already exists");

            var fileHash = await ObjectWriter.WriteAsync(_fileManager, new BlobObject(content));

            var newEntries = new Dictionary<string, TreeObject.Entry>();
            foreach (var (k, v) in tree.Entries) newEntries.Add(k, v);
            newEntries.Add(fileName, new TreeObject.Entry(0x81A4, fileName, fileHash));
            var newTree = new TreeObject(newEntries);

            var newTreeRef = await ObjectWriter.WriteAsync(_fileManager, newTree);

            var actor = new CommitObject.Actor("Test", "test@test.com", DateTimeOffset.UtcNow);
            var newCommit = new CommitObject(newTreeRef, new[] { commitRef }, actor, actor, "This is a test commit");
            var newCommitRef = await ObjectWriter.WriteAsync(_fileManager, newCommit);

            await SetHeadAsync(newCommitRef);
        }
    }
}
