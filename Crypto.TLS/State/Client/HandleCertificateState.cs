using System;
using System.Linq;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Handshakes;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State.Client
{
    public class HandleCertificateState : IState
    {
        public ConnectionState State => ConnectionState.RecievedServerCertificate;

        private readonly IServiceProvider _serviceProvider;
        
        private readonly EndConfig _endConfig;
        private readonly CertificateConfig _certificateConfig;

        private readonly CertificateMessage _handshake;

        private HandleCertificateState(
            IServiceProvider serviceProvider,
            
            EndConfig endConfig,
            CertificateConfig certificateConfig,

            CertificateMessage handshake)
        {
            _serviceProvider = serviceProvider;
            
            _endConfig = endConfig;
            _certificateConfig = certificateConfig;

            _handshake = handshake;
        }

        public static HandleCertificateState New(IServiceProvider serviceProvider, CertificateMessage handshake)
        {
            return new HandleCertificateState(
                serviceProvider,

                serviceProvider.GetRequiredService<EndConfig>(),
                serviceProvider.GetRequiredService<CertificateConfig>(),

                handshake);
        }

        public IState Run()
        {
            // TODO is it valid to receive this message?
            
            if (_endConfig.End == ConnectionEnd.Server)
            {
                throw new NotImplementedException();
            }
            
            _certificateConfig.CertificateChain = _handshake.Certificates.ToList();

            return _serviceProvider.GetRequiredService<WaitingForCertificateFollowupState>();
        }
    }
}