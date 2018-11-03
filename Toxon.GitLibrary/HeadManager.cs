using System;
using System.Buffers;
using System.Text;
using System.Threading.Tasks;
using Crypto.Utils;
using Toxon.Files;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary
{
    public class HeadManager
    {
        private static readonly ReadOnlyMemory<byte> Ref = Encoding.UTF8.GetBytes("ref: ").AsMemory();

        private readonly GitFileManager _fileManager;

        public HeadManager(GitFileManager fileManager)
        {
            _fileManager = fileManager;
        }

        public async Task<ObjectRef> ReadAsync()
        {
            var file = await GetHeadAsync();

            ReadOnlySequence<byte> buffer;
            using (var reader = file.OpenReader())
            {
                buffer = reader.ReadAll();
            }

            if (buffer.StartsWith(Ref.Span))
            {
                var refPathSlice = buffer.Slice(Ref.Length);
                var refPath = Encoding.UTF8.GetString(refPathSlice);

                var refManager = new RefManager(_fileManager);
                return await refManager.ReadAsync(refPath);
            }

            if (buffer.Length >= 40)
            {
                var hash = HexConverter.FromHex(buffer.Slice(0, 40));
                return new ObjectRef(hash);
            }

            throw new Exception("Invalid format");
        }

        private async Task<IFile> GetHeadAsync()
        {
            var file = await _fileManager.GetRootFileAsync("HEAD");
            if (!file.HasValue) throw new Exception("invalid repository");
            return file.Value;
        }

        public async Task WriterAsync(ObjectRef objectRef)
        {
            var file = await GetHeadAsync();
            using (var reader = file.OpenReader())
            {
                var header = reader.ReadExactly(Ref.Length);
                if (header.Span.StartsWith(Ref.Span))
                {
                    var refPathBuffer = reader.ReadAll();
                    var refPath = Encoding.UTF8.GetString(refPathBuffer);

                    var refManager = new RefManager(_fileManager);
                    await refManager.WriteAsync(refPath, objectRef);
                    return;
                }
            }

            var hash = HexConverter.ToHexBytes(objectRef.Hash);
            using (var writer = file.OpenWriter())
            {
                writer.Write(hash.Span);
            }
        }
    }
}
