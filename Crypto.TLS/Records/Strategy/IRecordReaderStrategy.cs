namespace Crypto.TLS.Records.Strategy
{
    public interface IRecordReaderStrategy
    {
        Record Read(RecordType type, TLSVersion version, ushort length);
    }
}