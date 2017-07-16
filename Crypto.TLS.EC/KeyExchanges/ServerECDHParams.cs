using Crypto.EC.Maths;
using Crypto.EC.Maths.Prime;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC.KeyExchanges
{
    public class ServerECDHParams
    {
        public ServerECDHParams(ECParameters curveParams, Point<PrimeValue> q)
        {
            CurveParams = curveParams;
            Q = q;
        }

        public ECParameters CurveParams { get; }
        // TODO PrimeValue should be configurable based on the curve
        public Point<PrimeValue> Q { get; }

        public void Write(EndianBinaryWriter writer)
        {
            CurveParams.Write(writer);
            writer.Write(Q);
        }
    }
}
