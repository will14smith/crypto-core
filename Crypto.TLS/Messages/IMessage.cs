using Crypto.TLS.Records;

namespace Crypto.TLS.Messages
{
    public interface IMessage
    {
        RecordType Type { get; }
    }
}
