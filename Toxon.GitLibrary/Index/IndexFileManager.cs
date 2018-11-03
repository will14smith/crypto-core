using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Toxon.GitLibrary.Index
{
    public class IndexFileManager
    {
        private readonly IndexFileSerializer _serializer;

        public IndexFileManager(GitFileManager fileManager)
        {
            _serializer = new IndexFileSerializer(fileManager);
        }

        public async Task<IReadOnlyCollection<IndexEntry>> ListAsync()
        {
            var index = await _serializer.ReadAsync();

            return index.Entries;
        }

        public async Task AddAsync(IndexEntry file)
        {
            // TODO lock?
            var index = await _serializer.ReadAsync();

            if (index.Entries.Any(x => x.Name == file.Name)) throw new Exception("File already added");

            var newEntries = new List<IndexEntry>(index.Entries) { file };

            var newIndex = new IndexFile(index.Version, newEntries, index.Extensions);
            await _serializer.WriteAsync(newIndex);
        }

        public async Task UpdateAsync(IndexEntry file)
        {
            // TODO lock?
            var index = await _serializer.ReadAsync();

            if (index.Entries.All(x => x.Name != file.Name)) throw new Exception("File doesn't exist");

            var newEntries = new List<IndexEntry>(index.Entries);
            var entryIndex = index.Entries.Select((x, i) => (x, i)).FirstOrDefault(x => x.x.Name == file.Name).i;
            newEntries[entryIndex] = file;

            var newIndex = new IndexFile(index.Version, newEntries, index.Extensions);
            await _serializer.WriteAsync(newIndex);
        }

        public async Task RemoveAsync(string name)
        {
            // TODO lock?
            var index = await _serializer.ReadAsync();

            if (index.Entries.All(x => x.Name != name)) throw new Exception("File doesn't exist");

            var newEntries = new List<IndexEntry>(index.Entries);
            var entryIndex = index.Entries.Select((x, i) => (x, i)).FirstOrDefault(x => x.x.Name == name).i;
            newEntries.RemoveAt(entryIndex);

            var newIndex = new IndexFile(index.Version, newEntries, index.Extensions);
            await _serializer.WriteAsync(newIndex);
        }
    }
}
