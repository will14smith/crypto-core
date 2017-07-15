using Crypto.TLS.Records;
using Crypto.Utils;

namespace Crypto.TLS.Messages.Alerts
{
    public class AlertMessage : IMessage
    {
        public RecordType Type => RecordType.Alert;
        public AlertLevel Level { get; }
        public AlertDescription Description { get; }

        public AlertMessage(AlertLevel level, AlertDescription description)
        {
            SecurityAssert.Assert(level.IsAllowed(description));

            Level = level;
            Description = description;
        }
        
        public static AlertMessage Read(byte[] data)
        {
            SecurityAssert.AssertBuffer(data, 0, 2);

            return new AlertMessage((AlertLevel)data[0], (AlertDescription)data[1]);
        }

        public byte[] GetBytes()
        {
            return new[]
            {
                (byte)Level,
                (byte)Description
            };
        }
    }
}
