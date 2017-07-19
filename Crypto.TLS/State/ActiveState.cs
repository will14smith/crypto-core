using System;

namespace Crypto.TLS.State
{
    public class ActiveState : IState
    {
        public ConnectionState State => ConnectionState.Active;
        
        public IState Run()
        {
            throw new NotSupportedException("Use this to detect handshake completion");
        }
    }
}