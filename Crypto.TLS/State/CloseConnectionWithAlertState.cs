using System;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Alerts;
using Crypto.TLS.Records;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.State
{
    public class CloseConnectionWithAlertState : IState
    {
        public ConnectionState State => ConnectionState.UnexpectedError;

        private readonly VersionConfig _versionConfig;
        private readonly Connection _connection;
        private readonly AlertMessage _alertMessage;

        public CloseConnectionWithAlertState(
            VersionConfig versionConfig,
            Connection connection,
            AlertMessage alertMessage)
        {
            _versionConfig = versionConfig;
            _connection = connection;
            _alertMessage = alertMessage;
        }

        public static CloseConnectionWithAlertState New(IServiceProvider serviceProvider, AlertMessage alertMessage)
        {
            return new CloseConnectionWithAlertState(
                versionConfig: serviceProvider.GetRequiredService<VersionConfig>(),
                connection: serviceProvider.GetRequiredService<Connection>(),
                alertMessage: alertMessage
            );
        }

        public IState Run()
        {
            _connection.WriteRecord(new Record(RecordType.Alert, _versionConfig.Version, _alertMessage.GetBytes()));
            return null;
        }
    }
}