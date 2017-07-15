using Crypto.Utils;

namespace Crypto.TLS.Records
{
    /// <summary>
    /// SENDING: unfragmented record
    /// RECIEVING fragmented record
    /// </summary>
    public class Record
    {
        public Record(RecordType type, TLSVersion version, byte[] data)
        {
            Type = type;
            Version = version;

            SecurityAssert.NotNull(data);
            Data = data;
        }

        public RecordType Type { get; }
        public TLSVersion Version { get; }
        public byte[] Data { get; }

        public int Length => Data.Length;
    }
}