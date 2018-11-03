using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Crypto.Utils;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary.Index
{
    public class IndexFileBuilder
    {
        private readonly IndexFileSerializer _serializer;
        private readonly ObjectManager _objectManager;
        private readonly HeadManager _headManager;

        public IndexFileBuilder(IndexFileSerializer serializer, ObjectManager objectManager, HeadManager headManager)
        {
            _serializer = serializer;
            _objectManager = objectManager;
            _headManager = headManager;
        }

        public async Task BuildIndexAsync(ObjectRef commitRef = null)
        {
            if (commitRef == null) commitRef = await _headManager.ReadAsync();
            var commit = (CommitObject)await _objectManager.ReadAsync(commitRef);

            var tree = (TreeObject)await _objectManager.ReadAsync(commit.Tree);
            var entries = await BuildEntriesAsync(commit, tree);

            var file = new IndexFile(2, entries, new IndexExtension[0]);
            await _serializer.WriteAsync(file);
        }

        private async Task<IReadOnlyList<IndexEntry>> BuildEntriesAsync(CommitObject commit, TreeObject tree, string treePath = "")
        {
            var entries = new List<IndexEntry>();

            foreach (var (_, treeEntry) in tree.Entries)
            {
                var obj = await _objectManager.ReadAsync(treeEntry.ObjectHash);
                var path = Path.Combine(treePath, treeEntry.Path);

                switch (obj)
                {
                    case BlobObject blobObject:
                        var date = commit.Committer.Timestamp.UtcDateTime;
                        var indexEntry = new IndexEntry(path, treeEntry.ObjectHash.Hash, (uint)blobObject.Content.Length, 0, treeEntry.Mode, date, date, 0, 0, 0, 0);
                        entries.Add(indexEntry);
                        break;
                    case TreeObject treeObject:
                        var objEntries = await BuildEntriesAsync(commit, treeObject, path);
                        entries.AddRange(objEntries);
                        break;

                    default: throw new ArgumentOutOfRangeException(nameof(obj));
                }

            }

            return entries;
        }
    }
}