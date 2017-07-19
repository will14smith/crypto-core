using System.IO;
using System.Threading;

namespace Crypto.TLS.IO
{
    public class StreamAccessor : IStreamAccessor
    {
        private static readonly AsyncLocal<Stream> stream = new AsyncLocal<Stream>();

        public Stream Stream
        {
            get => stream.Value;
            set => stream.Value = value;
        }
    }
}