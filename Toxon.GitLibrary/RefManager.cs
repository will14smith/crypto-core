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

        public async Task<ObjectRef> ReadAsync(string refPath)
        {
            var file = await _fileManager.GetRefAsync(refPath);
            if (!file.HasValue)
            {
                return await ReadPackedRefsAsync(refPath);
            }

            using (var reader = file.Value.OpenReader())
            {
                return await ReadAsync(reader);
            }
        }

        private static Task<ObjectRef> ReadAsync(Stream reader)
        {
            var buffer = reader.ReadExactly(40);
            if (buffer.Length < 40) throw new Exception("invalid format");

            var hash = HexConverter.FromHex(buffer.Span);
            return Task.FromResult(new ObjectRef(hash));
        }

        private async Task<ObjectRef> ReadPackedRefsAsync(string refPath)
        {
            var file = await _fileManager.GetRootFileAsync("packed-refs");
            if (!file.HasValue) throw new Exception("invalid ref");

            using (var input = file.Value.OpenReader())
            {
                var reader = new StreamReader(input);
                while (!reader.EndOfStream)
                {
                    var line = await reader.ReadLineAsync();
                    if (line.StartsWith("#")) continue;

                    var parts = line.Split(' ');
                    if (parts[1] != refPath) continue;

                    // TODO :( ToArray
                    var hash = HexConverter.FromHex(parts[0]).ToArray();
                    return new ObjectRef(hash);
                }
            }

            throw new Exception("invalid ref");
        }
        
        public async Task WriteAsync(string refPath, ObjectRef objectRef)
        {
            // TODO handle updating packed-refs

            var file = await _fileManager.CreateOrReplaceRefAsync(refPath);
            if (!file.HasValue) throw new Exception("error creating ref");

            using (var writer = file.Value.OpenWriter())
            {
                await WriteAsync(writer, objectRef);
            }
        }
        private Task WriteAsync(Stream writer, ObjectRef objectRef)
        {
            var hashString = HexConverter.ToHexBytes(objectRef.Hash);
            writer.Write(hashString.Span);

            return Task.CompletedTask;
        }
    }
}