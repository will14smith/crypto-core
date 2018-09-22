using System;
using Crypto.Utils;

namespace Crypto.TLS.Records.Strategy
{
    public class PlaintextStrategy : IRecordReaderStrategy, IRecordWriterStrategy
    {
        private readonly Connection _connection;

        public PlaintextStrategy(Connection connection)
        {
            _connection = connection;
        }

        public Record Read(RecordType type, TLSVersion version, ushort length)
        {
            SecurityAssert.Assert(length <= 0x4000);

            var data = _connection.Reader.ReadBytes(length);

            return new Record(type, version, data);
        }

        public void Write(RecordType type, TLSVersion version, ReadOnlySpan<byte> data)
        {
            _connection.Writer.Write(type);
            _connection.Writer.Write(version);
            _connection.Writer.Write((ushort)data.Length);
            _connection.Writer.Write(data);
        }
    }
}
