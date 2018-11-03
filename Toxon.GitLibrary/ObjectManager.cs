using System;
using System.Threading.Tasks;
using Toxon.GitLibrary.Objects;
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
            if (!objectFile.HasValue) throw new Exception("invalid object ref");

            using (var objectReader = objectFile.Value.OpenReader())
            {
                return ObjectReader.Read(objectRef, objectReader);
            }
        }

        public Task<ObjectRef> WriteAsync(Object obj)
        {
            throw new NotImplementedException();
        }
    }
}
