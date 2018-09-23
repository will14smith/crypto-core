using System.Collections.Generic;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Handshakes;

namespace Crypto.TLS.Extensions
{
    public class RenegotiationInfoExtension : IExtension
    {
        public const ExtensionType Type = (ExtensionType) 0xff01;

        private readonly EndConfig _endConfig;
        private readonly Config _config;

        public RenegotiationInfoExtension(EndConfig endConfig, Config config)
        {
            _endConfig = endConfig;
            _config = config;
        }

        public void HandleHello(HelloExtension hello)
        {
            _config.Data = hello.Data;
        }

        public IEnumerable<HelloExtension> GenerateHelloExtensions()
        {
            if (_endConfig.End == ConnectionEnd.Server && _config.Data == null)
            {
                yield break;
            }

            yield return new HelloExtension(Type, new byte[] { 0 });
        }

        public class Config
        {
            public byte[] Data { get; set; }
        }
    }
}
