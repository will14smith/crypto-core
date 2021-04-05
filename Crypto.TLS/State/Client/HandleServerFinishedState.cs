using System;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Services;
using Crypto.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State.Client
{
    public class HandleServerFinishedState : IState
    {
        public ConnectionState State => ConnectionState.RecievedServerFinished;

        private readonly IServiceProvider _serviceProvider;

        private readonly HandshakeFinishedService _handshakeFinishedService;


        private readonly FinishedMessage _handshake;

        public HandleServerFinishedState(
            IServiceProvider serviceProvider,

            HandshakeFinishedService handshakeFinishedService,

            FinishedMessage handshake)
        {
            _serviceProvider = serviceProvider;

            _handshakeFinishedService = handshakeFinishedService;

            _handshake = handshake;
        }

        public static HandleServerFinishedState New(IServiceProvider serviceProvider, FinishedMessage handshake)
        {
            return new HandleServerFinishedState(
                serviceProvider,

                serviceProvider.GetService<HandshakeFinishedService>(),

                handshake);
        }

        public IState Run()
        {
            SecurityAssert.Assert(_handshakeFinishedService.Verify(_handshake));

            return _serviceProvider.GetRequiredService<ActiveState>();
        }
    }
}