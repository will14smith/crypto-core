using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Crypto.Utils;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary
{
    public class TreeWalker
    {
        private readonly GitFileManager _fileManager;

        public TreeWalker(GitFileManager fileManager)
        {
            _fileManager = fileManager;
        }

        public async Task<IReadOnlyCollection<FileEntry>> WalkAsync(ObjectRef rootRef, TreeObject root, string rootPath = "")
        {
            var files = new List<FileEntry>();

            foreach (var (_, entry) in root.Entries)
            {
                // TODO don't need whole object
                var obj = await _fileManager.ReadObjectAsync(entry.ObjectHash);

                var path = Path.Combine(rootPath, entry.Path);

                switch (obj)
                {
                    case BlobObject _:
                        var file = new FileEntry(entry.Mode, path, rootRef, entry.ObjectHash);
                        files.Add(file);
                        break;

                    case TreeObject tree:
                        var subFiles = await WalkAsync(entry.ObjectHash, tree, path);
                        files.AddRange(subFiles);
                        break;

                    default: throw new Exception("invalid object in tree");
                }
            }

            return files;
        }

        public async Task<TreeObject> FindOrCreateTreeAsync(string path, TreeObject root)
        {
            if (path == "") return root;

            throw new NotImplementedException();
        }
    }
}
