using System.Collections.Generic;
using Crypto.ASN1;
using Crypto.EC.Maths.Prime;

namespace Crypto.TLS.EC.Services
{
    public class NamedCurvesRegistry
    {
        private readonly Dictionary<NamedCurve, PrimeDomainParameters> _curvesByEnum
            = new Dictionary<NamedCurve, PrimeDomainParameters>();
        private readonly Dictionary<ASN1ObjectIdentifier, PrimeDomainParameters> _curvesByOID
            = new Dictionary<ASN1ObjectIdentifier, PrimeDomainParameters>();

        public void Register(NamedCurve key, PrimeDomainParameters parameters)
        {
            _curvesByEnum.Add(key, parameters);
        }

        public PrimeDomainParameters Resolve(NamedCurve key)
        {
            return _curvesByEnum[key];
        }

        public bool IsSupported(NamedCurve key)
        {
            return _curvesByEnum.TryGetValue(key, out var _);
        }

        public void Register(ASN1ObjectIdentifier key, PrimeDomainParameters parameters)
        {
            _curvesByOID.Add(key, parameters);
        }

        public PrimeDomainParameters Resolve(ASN1ObjectIdentifier key)
        {
            return _curvesByOID[key];
        }

        public bool IsSupported(ASN1ObjectIdentifier key)
        {
            return _curvesByOID.TryGetValue(key, out var _);
        }

        public void Register(NamedCurve id, ASN1ObjectIdentifier oid, PrimeDomainParameters parameters)
        {
            Register(id, parameters);
            Register(oid, parameters);
        }
    }
}
