using System;
using System.Collections.Generic;
using Crypto.ASN1;
using Crypto.Core.Registry;
using Crypto.EC.Maths.Prime;

namespace Crypto.EC.Services
{
    public class NamedCurvesRegistry : IRegistry<NamedCurve, PrimeDomainParameters>, IRegistry<ASN1ObjectIdentifier, PrimeDomainParameters>
    {
        private readonly Dictionary<NamedCurve, Func<IServiceProvider, PrimeDomainParameters>> _curvesByEnum
            = new Dictionary<NamedCurve, Func<IServiceProvider, PrimeDomainParameters>>();
        private readonly Dictionary<ASN1ObjectIdentifier, Func<IServiceProvider, PrimeDomainParameters>> _curvesByOID
            = new Dictionary<ASN1ObjectIdentifier, Func<IServiceProvider, PrimeDomainParameters>>();

        public void Register(NamedCurve key, Func<IServiceProvider, PrimeDomainParameters> factory)
        {
            _curvesByEnum.Add(key, factory);
        }

        public PrimeDomainParameters Resolve(IServiceProvider serviceProvider, NamedCurve key)
        {
            return _curvesByEnum[key](serviceProvider);
        }

        public bool IsSupported(NamedCurve key)
        {
            return _curvesByEnum.TryGetValue(key, out var _);
        }

        public void Register(ASN1ObjectIdentifier key, Func<IServiceProvider, PrimeDomainParameters> factory)
        {
            _curvesByOID.Add(key, factory);
        }

        public PrimeDomainParameters Resolve(IServiceProvider serviceProvider, ASN1ObjectIdentifier key)
        {
            return _curvesByOID[key](serviceProvider);
        }

        public bool IsSupported(ASN1ObjectIdentifier key)
        {
            return _curvesByOID.TryGetValue(key, out var _);
        }
    }
}
