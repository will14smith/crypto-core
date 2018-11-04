using System.Threading.Tasks;
using Crypto.Core.Hashing;
using Crypto.SHA;
using Crypto.Utils;

namespace Toxon.GitLibrary.Objects
{
    public static class ObjectWriter
    {

        public static async Task<ObjectRef> WriteAsync(GitFileManager fileManager, Object obj)
        {
            var objBuffer = obj.ToBuffer();

            var digest = new SHA1Digest();
            digest.Update(objBuffer);
            var hash = SequenceExtensions.Create<byte>(digest.Digest().ToArray());

            var objectRef = new ObjectRef(hash);

            var file = await fileManager.CreateObjectAsync(objectRef);
            if (!file.HasValue) return objectRef;


            using (var writer = file.Value.OpenWriter())
            {
                Zlib.Deflate(writer, objBuffer);
            }

            return objectRef;
        }
    }
}
