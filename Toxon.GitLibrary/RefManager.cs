using System;
using System.IO;
using System.Threading.Tasks;
using Crypto.Utils;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary
{
    public class RefManager
    {
        private readonly GitFileManager _fileManager;

        public RefManager(GitFileManager fileManager)
        {
            _fileManager = fileManager;
        }

        public static Task<ObjectRef> ReadAsync(Stream reader)
        {
            var buffer = reader.ReadExactly(40);
            if (buffer.Length < 40) throw new Exception("Invalid format");

            var hash = HexConverter.FromHex(buffer.Span);
            return Task.FromResult(new ObjectRef(hash));
        }

        public async Task<ObjectRef> ReadAsync(string refPath)
        {
            var file = await _fileManager.GetRefAsync(refPath);
            if (!file.HasValue) throw new Exception("Invalid ref");

            using (var reader = file.Value.OpenReader())
            {
                return await ReadAsync(reader);
            }
        }

        public Task WriteAsync(Stream writer, ObjectRef objectRef)
        {
            var hashString = HexConverter.ToHexBytes(objectRef.Hash);
            writer.Write(hashString.Span);

            return Task.CompletedTask;
        }

        public async Task WriteAsync(string refPath, ObjectRef objectRef)
        {
            var file = await _fileManager.CreateOrReplaceRefAsync(refPath);
            if (!file.HasValue) throw new Exception("Invalid ref");

            using (var writer = file.Value.OpenWriter())
            {
                await WriteAsync(writer, objectRef);
            }
        }
    }
}