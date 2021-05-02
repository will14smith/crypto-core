using System;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Alerts;
using Crypto.TLS.Records;
using Crypto.TLS.Suites;
using Crypto.TLS.Suites.Providers;
using Crypto.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State.Server
{
    public class WaitingForClientChangeCipherSpecState : ReadingState
    {
        public override ConnectionState State => ConnectionState.WaitingForClientChangeCipherSpec;

        private readonly ICipherSuitesProvider _cipherSuitesProvider;
        private readonly CipherSuiteConfig _cipherSuiteConfig;

        public WaitingForClientChangeCipherSpecState(
            IServiceProvider serviceProvider,
            ICipherSuitesProvider cipherSuitesProvider,

            CipherSuiteConfig cipherSuiteConfig,
            Connection connection)
            : base(serviceProvider, connection)
        {
            _cipherSuitesProvider = cipherSuitesProvider;
            _cipherSuiteConfig = cipherSuiteConfig;
        }

        protected override Option<IState> HandleRecord(Record record)
        {
            switch (record.Type)
            {
                case RecordType.ChangeCipherSpec:
                    return Option.Some(HandleChangeCipherSpec(record));
                case RecordType.Alert:
                    return HandleAlert(record);
                default:
                    return UnexpectedMessage();
            }
        }

        private IState HandleChangeCipherSpec(Record record)
        {
            SecurityAssert.Assert(record.Length == 1);
            SecurityAssert.Assert(record.Data[0] == 1);

            Connection.RecordReaderStrategy = _cipherSuitesProvider.GetRecordReaderStrategy(ServiceProvider, _cipherSuiteConfig.CipherSuite);

            return ServiceProvider.GetRequiredService<WaitingForClientFinishedState>();
        }

        private Option<IState> HandleAlert(Record record)
        {
            // TODO any alerts we can handle?
            // TODO report alert to external handler?
            var alert = AlertMessage.Read(record.Data);
            return UnexpectedMessage(alert);
        }
    }
}