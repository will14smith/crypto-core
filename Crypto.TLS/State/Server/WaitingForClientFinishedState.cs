﻿using System;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Records;
using Crypto.Utils;

namespace Crypto.TLS.State.Server
{
    public class WaitingForClientFinishedState : ReadingState
    {
        public override ConnectionState State => ConnectionState.WaitingForClientFinished;

        private readonly HandshakeReader _reader;

        public WaitingForClientFinishedState(
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

            if (handshake.HandshakeType != HandshakeType.Finished)
            {
                return UnexpectedMessage();
            }

            return Option.Some<IState>(HandleClientFinishedState.New(ServiceProvider, (FinishedMessage)handshake));
        }

        private Option<IState> HandleAlert(Record record)
        {
            // TODO any alerts we can handle?
            // TODO report alert to external handler?

            return UnexpectedMessage();
        }
    }
}
