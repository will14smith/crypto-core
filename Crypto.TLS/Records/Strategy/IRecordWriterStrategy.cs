using System;

namespace Crypto.TLS.Records.Strategy
{
    public interface IRecordWriterStrategy
    {
        void Write(RecordType type, TLSVersion version, ReadOnlySpan<byte> data);
    }
}
