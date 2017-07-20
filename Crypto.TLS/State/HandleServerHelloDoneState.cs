using System;
using Crypto.TLS.Messages.Handshakes;

namespace Crypto.TLS.State
{
    public class HandleServerHelloDoneState : IState
    {
        public ConnectionState State => ConnectionState.RecievedServerHelloDone;

        private ServerHelloDoneMessage _handshake;

        public HandleServerHelloDoneState(ServerHelloDoneMessage handshake)
        {
            _handshake = handshake;
        }

        public static HandleServerHelloDoneState New(IServiceProvider serviceProvider, ServerHelloDoneMessage handshake)
        {
            return new HandleServerHelloDoneState(
                handshake);
        }

        public IState Run()
        {
            throw new NotImplementedException();
        }
    }
}