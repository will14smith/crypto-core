using System.Text;
using Crypto.Utils;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary
{
    public class FileEntry
    {
        public FileEntry(ushort mode, string path, ObjectRef tree, ObjectRef blob)
        {
            Mode = mode;
            Path = path;

            Tree = tree;
            Blob = blob;
        }

        public ushort Mode { get; }
        public string Path { get; }

        public ObjectRef Tree { get; }
        public ObjectRef Blob { get; }

        public override string ToString()
        {
            var modeStr = Encoding.UTF8.GetString(TreeObject.FormatOctalMode(Mode));

            return $"{modeStr} {Path} {HexConverter.ToHex(Blob.Hash.Slice(0, 4))}";
        }
    }
}