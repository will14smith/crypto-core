﻿using Crypto.Core.Registry;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.Services
{
    public class CipherParameterFactoryRegistry : BaseRegistry<TLSCipherAlgorithm, ICipherParameterFactory>
    {
    }
}