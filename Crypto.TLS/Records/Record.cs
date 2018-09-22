using System;
using Crypto.Utils;

namespace Crypto.TLS.Records
{
    /// <summary>
    /// SENDING: unfragmented record
    /// RECIEVING fragmented record
    /// </summary>
    public class Record
    {
        public Record(RecordType type, TLSVersion version, ReadOnlyMemory<byte> data)
        {
            Type = type;
            Version = version;

            SecurityAssert.NotNull(data);
            Data = data;
        }

        public RecordType Type { get; }
        public TLSVersion Version { get; }
        public ReadOnlyMemory<byte> Data { get; }

        public int Length => Data.Length;
    }
}