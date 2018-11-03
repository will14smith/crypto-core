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

        private ObjectManager Objects => new ObjectManager(_fileManager);

        private IndexFileManager IndexFile => new IndexFileManager(_fileManager);
        private IndexManager Index => new IndexManager(IndexFile);
        public StagingManager Staging => new StagingManager(_fileManager, Index);

        public async Task<IReadOnlyCollection<CommitObject>> GetParentCommitsAsync(ObjectRef commitRef = null)
        {
            if (commitRef == null)
                commitRef = await GetHeadAsync();
            var commit = (CommitObject)await Objects.ReadAsync(commitRef);

            var commits = new List<CommitObject>();
            while (true)
            {
                commits.Add(commit);

                var parentRef = commit.Parents.SingleOrDefault();
                if (parentRef == null) break;

                commit = (CommitObject)await Objects.ReadAsync(parentRef);
            }

            return commits;
        }

        public async Task<IReadOnlyCollection<FileEntry>> GetFilesAsync(ObjectRef commitRef = null)
        {
            if (commitRef == null)
                commitRef = await GetHeadAsync();
            var commit = (CommitObject)await Objects.ReadAsync(commitRef);

            var tree = (TreeObject)await Objects.ReadAsync(commit.Tree);
            var walker = new TreeWalker(Objects);

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
    }
}
