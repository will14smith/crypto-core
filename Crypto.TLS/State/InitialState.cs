using System;
using Crypto.TLS.Config;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State
{
    public class InitialState : IState
    {
        public ConnectionState State => ConnectionState.Initial;

        private readonly IServiceProvider _serviceProvider;
        
        private readonly EndConfig _endConfig;
        
        public InitialState(
            IServiceProvider serviceProvider,
            
            EndConfig endConfig)
        {
            _serviceProvider = serviceProvider;
            
            _endConfig = endConfig;
        }

        public IState Run()
        {
            _endConfig.End = ConnectionEnd.Server;
            
            return _serviceProvider.GetRequiredService<WaitingForClientHelloState>();
        }
    }
}
