using System;
using Crypto.TLS.Config;
using Crypto.TLS.Records;
using Crypto.TLS.Services;
using Crypto.TLS.Suites;
using Crypto.TLS.Suites.Providers;
using Crypto.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State
{
    public class WaitingForServerChangeCipherSpecState : ReadingState
    {
        public override ConnectionState State => ConnectionState.WaitingForServerChangeCipherSpec;

        private readonly ICipherSuitesProvider _cipherSuitesProvider;
        private readonly CipherSuiteConfig _cipherSuiteConfig;

        public WaitingForServerChangeCipherSpecState(
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
            SecurityAssert.Assert(record.Data.Span[0] == 1);

            Connection.RecordReaderStrategy = _cipherSuitesProvider.GetRecordReaderStrategy(ServiceProvider, _cipherSuiteConfig.CipherSuite);

            return ServiceProvider.GetRequiredService<WaitingForServerFinishedState>();
        }

        private Option<IState> HandleAlert(Record record)
        {
            // TODO any alerts we can handle?
            // TODO report alert to external handler?

            return UnexpectedMessage();
        }
    }
}