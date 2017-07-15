using System.IO;

namespace Crypto.TestProgram
{
    public interface IStreamAccessor
    {
        Stream Stream { get; set; }
    }
}