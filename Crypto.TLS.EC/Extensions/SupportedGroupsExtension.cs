using System;
using System.Collections.Generic;
using Crypto.TLS.Config;
using Crypto.TLS.EC.Config;
using Crypto.TLS.EC.Services;
using Crypto.TLS.Extensions;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;

namespace Crypto.TLS.EC.Extensions
{
    public class SupportedGroupsExtension : IExtension
    {
        private readonly SupportedGroupsConfig _supportedGroupsConfig;
        private readonly EndConfig _endConfig;

        public SupportedGroupsExtension(
            SupportedGroupsConfig supportedGroupsConfig,
            EndConfig endConfig)
        {
            _supportedGroupsConfig = supportedGroupsConfig;
            _endConfig = endConfig;
        }
        
        public IEnumerable<HelloExtension> GenerateHelloExtensions()
        {
            if (_endConfig.End == ConnectionEnd.Server)
            {
                yield break;
            }
            
            throw new NotImplementedException();
        }

        public void HandleHello(HelloExtension hello)
        {
            SecurityAssert.Assert(_endConfig.End == ConnectionEnd.Server);
            
            SecurityAssert.Assert(hello.Data.Length > 2);
            var length = EndianBitConverter.Big.ToUInt16(hello.Data, 0);
            SecurityAssert.Assert(length > 1 && hello.Data.Length == length + 2);

            var list = new List<NamedCurve>();
            for (var i = 2; i < hello.Data.Length; i += 2)
            {
                var id = EndianBitConverter.Big.ToUInt16(hello.Data, i);
                list.Add((NamedCurve) id);
            }

            _supportedGroupsConfig.SupportedGroups = list;
        }
    }
}
