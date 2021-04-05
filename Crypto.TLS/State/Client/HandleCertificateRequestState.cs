using System;
using Crypto.TLS.Messages.Handshakes;

namespace Crypto.TLS.State.Client
{
    public class HandleCertificateRequestState : IState
    {
        public ConnectionState State => ConnectionState.RecievedServerCertificateRequest;

        private readonly CertificateRequestMessage _handshake;

        private HandleCertificateRequestState(CertificateRequestMessage handshake)
        {
            _handshake = handshake;
        }

        public static HandleCertificateRequestState New(IServiceProvider serviceProvider, CertificateRequestMessage handshake)
        {
            return new HandleCertificateRequestState(
                handshake);
        }

        public IState Run()
        {
            // TODO is it valid to receive this message?

            throw new NotImplementedException();
        }
    }
}