using System.Buffers;
using System.IO;
using Crypto.Core.Hashing;
using Crypto.SHA;
using Crypto.Utils;
using Toxon.Files;

namespace Toxon.GitLibrary
{
    public static class HashExtensions
    {
        public static ReadOnlySequence<byte> Hash(this Stream reader)
        {
            var fileData = reader.ReadAll();

            var digest = new SHA1Digest();
            digest.Update(fileData);
            return SequenceExtensions.Create<byte>(digest.Digest().ToArray());
        }
        public static ReadOnlySequence<byte> Hash(this IFile file)
        {
            using (var reader = file.OpenReader())
            {
                return reader.Hash();
            }
        }
    }
}
