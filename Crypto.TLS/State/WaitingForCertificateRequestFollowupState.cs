using System;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Records;
using Crypto.Utils;

namespace Crypto.TLS.State
{
    public class WaitingForCertificateRequestFollowupState : ReadingState
    {
        public override ConnectionState State => ConnectionState.WaitingForServerCertificateRequestFollowup;

        private readonly HandshakeReader _reader;

        public WaitingForCertificateRequestFollowupState(
            IServiceProvider serviceProvider,

            Connection connection,
            HandshakeReader reader)
            : base(serviceProvider, connection)
        {
            _reader = reader;
        }

        protected override Option<IState> HandleRecord(Record record)
        {
            switch (record.Type)
            {
                case RecordType.Handshake:
                    return HandleHandshake(record);
                case RecordType.Alert:
                    return HandleAlert(record);
                default:
                    return UnexpectedMessage();
            }
        }

        private Option<IState> HandleHandshake(Record record)
        {
            var handshake = _reader.Read(record);

            switch (handshake.HandshakeType)
            {
                case HandshakeType.ServerHelloDone:
                    return Option.Some<IState>(HandleServerHelloDoneState.New(ServiceProvider, (ServerHelloDoneMessage)handshake));
                default:
                    return UnexpectedMessage();
            }
        }

        private Option<IState> HandleAlert(Record record)
        {
            // TODO any alerts we can handle?
            // TODO report alert to external handler?

            return UnexpectedMessage();
        }
    }
}