using System.IO;

namespace Crypto.TLS.IO
{
    public interface IStreamAccessor
    {
        Stream Stream { get; set; }
    }
}