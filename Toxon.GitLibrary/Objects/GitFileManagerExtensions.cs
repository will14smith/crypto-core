using System;
using System.Threading.Tasks;

namespace Toxon.GitLibrary.Objects
{
    public static class GitFileManagerExtensions
    {
        public static async Task<Object> ReadObjectAsync(this GitFileManager fileManager, ObjectRef objectRef)
        {
            var objectFile = await fileManager.GetObjectAsync(objectRef);
            if (!objectFile.HasValue) throw new Exception("invalid object ref");

            using (var objectReader = objectFile.Value.OpenReader())
            {
                return ObjectReader.Read(objectRef, objectReader);
            }

        }
    }
}