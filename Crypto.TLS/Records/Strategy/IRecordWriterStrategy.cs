namespace Crypto.TLS.Records.Strategy
{
    public interface IRecordWriterStrategy
    {
        void Write(RecordType type, TLSVersion version, byte[] data);
    }
}
