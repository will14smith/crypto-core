using System.Linq;
using System.Threading.Tasks;
using Toxon.Files;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary.Index
{
    public class IndexManager
    {
        public IndexFileManager Raw { get; }

        public IndexManager(IndexFileManager index)
        {
            Raw = index;
        }

        public async Task<IndexEntry> StageAsync(IFile file, ObjectRef objectRef = null)
        {
            var path = file.Info.RootRelativePath;
            var hash = objectRef?.Hash ?? file.Hash();
            var size = file.Info.Size;
            var created = file.Info.Created;
            var modified = file.Info.Modified;

            var entry = new IndexEntry(path, hash, size, 0, 0x81a4, created, modified, 0, 0, 0, 0);

            // TODO move this inside the IndexFileManager?
            var existing = await Raw.ListAsync();
            var exists = existing.Any(x => x.Name == entry.Name);

            if (!exists) await Raw.AddAsync(entry);
            else await Raw.UpdateAsync(entry);

            return entry;
        }

        public async Task RemoveAsync(string name)
        {
            await Raw.RemoveAsync(name);
        }
    }
}
