using System;
using System.Collections.Generic;
using System.IO;
using Crypto.TLS.Config;
using Crypto.TLS.EC.Config;
using Crypto.TLS.EC.Services;
using Crypto.TLS.Extensions;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC.Extensions
{
    public class SupportedGroupsExtension : IExtension
    {
        private readonly NamedCurvesRegistry _namedCurvesRegistry;
        
        private readonly SupportedGroupsConfig _supportedGroupsConfig;
        private readonly EndConfig _endConfig;

        public SupportedGroupsExtension(
            NamedCurvesRegistry namedCurvesRegistry,
            
            SupportedGroupsConfig supportedGroupsConfig,
            EndConfig endConfig)
        {
            _namedCurvesRegistry = namedCurvesRegistry;
            
            _supportedGroupsConfig = supportedGroupsConfig;
            _endConfig = endConfig;
        }
        
        public IEnumerable<HelloExtension> GenerateHelloExtensions()
        {
            if (_endConfig.End == ConnectionEnd.Server)
            {
                yield break;
            }

            var groups = _namedCurvesRegistry.GetAllSupportedNamedCurves();
            
            using (var ms = new MemoryStream())
            {
                var writer = new EndianBinaryWriter(EndianBitConverter.Big, ms);

                writer.Write((ushort)(groups.Count * 2));
                foreach (var group in groups)
                {
                    writer.Write((ushort)group);
                }

                yield return new HelloExtension(ECIdentifiers.SupportedGroups, ms.ToArray());
            }
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
