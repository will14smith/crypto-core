using System.Collections.Generic;
using Crypto.TLS.Messages.Handshakes;

namespace Crypto.TLS.Extensions
{
    public interface IExtension
    {
        IEnumerable<HelloExtension> GenerateHelloExtensions();
        void HandleHello(HelloExtension hello);
    }
}
