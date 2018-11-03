using System.Buffers;
using System.Text;
using Crypto.Utils;

namespace Toxon.GitLibrary.Objects
{
    public class BlobObject : Object
    {
        public override ObjectType Type => ObjectType.Blob;

        public ReadOnlySequence<byte> Content { get; }

        public BlobObject(in ReadOnlySequence<byte> content)
        {
            Content = content;
        }

        public override ReadOnlySequence<byte> ToBuffer()
        {
            var prefix = Encoding.UTF8.GetBytes("blob " + Content.Length);

            return SequenceExtensions.Create<byte>(prefix, new byte[] { 0 }).Concat(Content);
        }
    }
}