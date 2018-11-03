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
        private readonly GitFileManager _fileManager;

        public IndexFileBuilder(IndexFileSerializer serializer, GitFileManager fileManager)
        {
            _serializer = serializer;
            _fileManager = fileManager;
        }

        public async Task BuildIndexAsync(ObjectRef commitRef = null)
        {
            if (commitRef == null) commitRef = await new HeadManager(_fileManager).ReadAsync();
            var commit = (CommitObject)await _fileManager.ReadObjectAsync(commitRef);

            var tree = (TreeObject)await _fileManager.ReadObjectAsync(commit.Tree);
            var entries = await BuildEntriesAsync(commit, tree);

            var file = new IndexFile(2, entries, new IndexExtension[0]);
            await _serializer.WriteAsync(file);
        }

        private async Task<IReadOnlyList<IndexEntry>> BuildEntriesAsync(CommitObject commit, TreeObject tree, string treePath = "")
        {
            var entries = new List<IndexEntry>();

            foreach (var (_, treeEntry) in tree.Entries)
            {
                var obj = await _fileManager.ReadObjectAsync(treeEntry.ObjectHash);
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