using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary.Index
{
    public class StagingCommitter
    {
        private readonly IndexManager _index;
        private readonly ObjectManager _objectManager;
        private readonly HeadManager _headManager;

        public StagingCommitter(IndexManager index, ObjectManager objectManager, HeadManager headManager)
        {
            _index = index;
            _objectManager = objectManager;
            _headManager = headManager;
        }

        public async Task<CommitObject> CommitAsync(CommitObject.Actor author, CommitObject.Actor committer, string message)
        {
            var entries = await _index.Raw.ListAsync();
            var rootTree = await BuildTreeFromEntriesAsync(entries);
            var parents = new[] { await _headManager.ReadAsync() };

            var commit = new CommitObject(rootTree, parents, author, committer, message);
            var commitRef = await _objectManager.WriteAsync(commit);
            await _headManager.WriterAsync(commitRef);

            return commit;
        }

        private async Task<ObjectRef> BuildTreeFromEntriesAsync(IEnumerable<IndexEntry> entries)
        {
            var mode = (ushort)0x81a4;
            var root = new TreeNode.Internal("", mode);

            foreach (var entry in entries)
            {
                var path = Path.GetDirectoryName(entry.Name)?.Split(Path.PathSeparator);
                var fileName = Path.GetFileName(entry.Name);

                var node = root.Find(path);
                node.Add(new TreeNode.Leaf(new TreeObject.Entry(mode, fileName, new ObjectRef(entry.Hash))));
            }

            return await WriteInternalNodeAsync(root);
        }

        private async Task<ObjectRef> WriteInternalNodeAsync(TreeNode.Internal node)
        {
            var entries = new Dictionary<string, TreeObject.Entry>();

            foreach (var child in node.Children)
            {
                switch (child)
                {
                    case TreeNode.Internal internalNode:
                        var internalRef = await WriteInternalNodeAsync(internalNode);
                        entries.Add(internalNode.Name, new TreeObject.Entry(internalNode.Mode, internalNode.Name, internalRef));

                        break;
                    case TreeNode.Leaf leafNode: entries.Add(leafNode.Entry.Path, leafNode.Entry); break;
                }
            }

            var tree = new TreeObject(entries);
            return await _objectManager.WriteAsync(tree);
        }

        private abstract class TreeNode
        {
            public class Internal : TreeNode
            {
                public Internal(string name, ushort mode)
                {
                    Name = name;
                    Mode = mode;
                }

                public string Name { get; }
                public ushort Mode { get; }

                public List<TreeNode> Children { get; } = new List<TreeNode>();

                public Internal Find(ReadOnlySpan<string> path)
                {
                    if (path.IsEmpty || (path.Length == 1 && path[0] == "")) return this;

                    throw new NotImplementedException();
                }

                public void Add(TreeNode leaf)
                {
                    Children.Add(leaf);
                }
            }

            public class Leaf : TreeNode
            {
                public Leaf(TreeObject.Entry entry)
                {
                    Entry = entry;
                }

                public TreeObject.Entry Entry { get; }
            }
        }
    }
}