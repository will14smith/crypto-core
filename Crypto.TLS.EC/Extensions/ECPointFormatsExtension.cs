using System.Collections.Generic;
using System.Linq;
using Crypto.TLS.Config;
using Crypto.TLS.EC.Config;
using Crypto.TLS.Extensions;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;

namespace Crypto.TLS.EC.Extensions
{
    public class ECPointFormatsExtension : IExtension
    {
        private readonly EndConfig _endConfig;
        private readonly ECPointFormatsConfig _ecPointFormatsConfig;

        public ECPointFormatsExtension(
            EndConfig endConfig,
            ECPointFormatsConfig ecPointFormatsConfig)
        {
            _endConfig = endConfig;
            _ecPointFormatsConfig = ecPointFormatsConfig;
        }

        public IEnumerable<HelloExtension> GenerateHelloExtensions()
        {
            if (_endConfig.End == ConnectionEnd.Server && (_ecPointFormatsConfig.SupportedPointFormats == null || !_ecPointFormatsConfig.SupportedPointFormats.Any()))
            {
                // client doesn't support EC
                yield break;
            }
            
            // This need kept in sync with Crypto.EC.Maths.CurveExtensions.PointFromBinary
            var localSupportedFormats = new[]
            {
                ECPointFormat.Uncompressed
            };

            var data = new[] { (byte)localSupportedFormats.Length }
                .Concat(localSupportedFormats.Cast<byte>())
                .ToArray();
            yield return new HelloExtension(ECIdentifiers.ECPointFormats, data);
        }

        public void HandleHello(HelloExtension hello)
        {
            SecurityAssert.Assert(hello.Data.Length > 1);
            var length = hello.Data[0];
            SecurityAssert.Assert(length > 0 && hello.Data.Length == length + 1);

            var list = new List<ECPointFormat>();
            for (var i = 1; i < hello.Data.Length; i++)
            {
                list.Add((ECPointFormat)hello.Data[i]);
            }

            _ecPointFormatsConfig.SupportedPointFormats = list;
        }
    }
}
