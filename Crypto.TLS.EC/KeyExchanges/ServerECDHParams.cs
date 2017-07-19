using Crypto.EC.Maths;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC.KeyExchanges
{
    public class ServerECDHParams
    {
        public ServerECDHParams(ECParameters curveParams, Point q)
        {
            CurveParams = curveParams;
            Q = q;
        }

        public ECParameters CurveParams { get; }
        public Point Q { get; }

        public void Write(EndianBinaryWriter writer)
        {
            CurveParams.Write(writer);
            writer.Write(Q);
        }
    }
}
