using System.IO;
using Crypto.TLS.Records;
using Crypto.TLS.Records.Strategy;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS
{
    public class Connection
    {
        private readonly Stream _stream;

        public Connection(Stream stream)
        {
            _stream = stream;

            Reader = new EndianBinaryReader(EndianBitConverter.Big, stream);
            Writer = new EndianBinaryWriter(EndianBitConverter.Big, stream);

            RecordReaderStrategy = new PlaintextStrategy(this);
            RecordWriterStrategy = new PlaintextStrategy(this);
        }

        public EndianBinaryReader Reader { get; }
        public EndianBinaryWriter Writer { get; }

        public IRecordReaderStrategy RecordReaderStrategy { get; set; }
        public IRecordWriterStrategy RecordWriterStrategy { get; set; }

        public Record ReadRecord()
        {
            var type = Reader.ReadRecordType();
            var version = Reader.ReadVersion();
            var length = Reader.ReadUInt16();

            return RecordReaderStrategy.Read(type, version, length);
        }

        public void WriteRecord(Record record)
        {
            RecordWriterStrategy.Write(record.Type, record.Version, record.Data);
        }
    }
}
