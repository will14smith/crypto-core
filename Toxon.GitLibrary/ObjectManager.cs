using System;
using System.IO;
using System.Threading.Tasks;
using Toxon.GitLibrary.Objects;
using Toxon.GitLibrary.Packs;
using Object = Toxon.GitLibrary.Objects.Object;

namespace Toxon.GitLibrary
{
    public class ObjectManager
    {
        private readonly GitFileManager _fileManager;

        public ObjectManager(GitFileManager fileManager)
        {
            _fileManager = fileManager;
        }

        public async Task<Object> ReadAsync(ObjectRef objectRef)
        {
            var objectFile = await _fileManager.GetObjectAsync(objectRef);
            if (!objectFile.HasValue) { return await ReadPackedAsync(objectRef); }

            using (var objectReader = objectFile.Value.OpenReader())
            {
                return ObjectReader.Read(objectRef, objectReader);
            }
        }

        private async Task<Object> ReadPackedAsync(ObjectRef objectRef)
        {
            var packDirectory = await _fileManager.GetPackDirectory();
            if (!packDirectory.HasValue) throw new Exception("invalid object ref");

            var indexFiles = packDirectory.Value.GetFiles("*.idx");
            foreach (var indexFile in indexFiles)
            {
                PackIndex index;
                using (var reader = indexFile.OpenReader())
                {
                    index = PackIndexSerializer.Read(reader);
                }

                var offset = index.LookupOffset(objectRef);
                if (!offset.HasValue) continue;

                var packFileName = Path.GetFileNameWithoutExtension(indexFile.Info.RootRelativePath);
                var packFile = packDirectory.Value.GetFile($"{packFileName}.pack");
                if (!packDirectory.HasValue) throw new Exception("invalid pack index");

                using (var reader = packFile.Value.OpenReader())
                {
                    return PackFileSerializer.ReadObject(reader, index, offset.Value);
                }
            }

            throw new Exception("invalid object ref");
        }

        public Task<ObjectRef> WriteAsync(Object obj)
        {
            throw new NotImplementedException();
        }
    }
}
