using System.Collections.Generic;
using Crypto.ASN1;
using Crypto.EC.Maths;

namespace Crypto.TLS.EC.Services
{
    public class NamedCurvesRegistry
    {
        private readonly Dictionary<NamedCurve, DomainParameters> _curvesByEnum
            = new Dictionary<NamedCurve, DomainParameters>();
        private readonly Dictionary<ASN1ObjectIdentifier, DomainParameters> _curvesByOID
            = new Dictionary<ASN1ObjectIdentifier, DomainParameters>();

        public void Register(NamedCurve key, DomainParameters parameters)
        {
            _curvesByEnum.Add(key, parameters);
        }

        public DomainParameters Resolve(NamedCurve key)
        {
            return _curvesByEnum[key];
        }

        public bool IsSupported(NamedCurve key)
        {
            return _curvesByEnum.TryGetValue(key, out var _);
        }

        public void Register(ASN1ObjectIdentifier key, DomainParameters parameters)
        {
            _curvesByOID.Add(key, parameters);
        }

        public DomainParameters Resolve(ASN1ObjectIdentifier key)
        {
            return _curvesByOID[key];
        }

        public bool IsSupported(ASN1ObjectIdentifier key)
        {
            return _curvesByOID.TryGetValue(key, out var _);
        }

        public void Register(NamedCurve id, ASN1ObjectIdentifier oid, DomainParameters parameters)
        {
            Register(id, parameters);
            Register(oid, parameters);
        }

        public bool FindNameByParameters(DomainParameters parameters, out NamedCurve name)
        {
            foreach (var entry in _curvesByEnum)
            {
                if (entry.Value.Equals(parameters))
                {
                    name = entry.Key;
                    return true;
                }
            }

            name = default(NamedCurve);
            return false;
        }

        public IReadOnlyCollection<NamedCurve> GetAllSupportedNamedCurves()
        {
            return _curvesByEnum.Keys;
        }
    }
}
