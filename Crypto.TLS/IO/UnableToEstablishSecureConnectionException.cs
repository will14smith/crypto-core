using System;
using Crypto.TLS.Messages.Alerts;

namespace Crypto.TLS.IO
{
    public class UnableToEstablishSecureConnectionException : Exception
    {
        public AlertMessage AlertMessage { get; }

        public UnableToEstablishSecureConnectionException(AlertMessage alertMessage)
            : base((string) $"Unable to establish secure connection, closed connection with alert {alertMessage.Level} {alertMessage.Description}")
        {
            AlertMessage = alertMessage;
        }
    }
}