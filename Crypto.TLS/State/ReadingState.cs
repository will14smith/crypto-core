using System;
using Crypto.TLS.Messages.Alerts;
using Crypto.TLS.Records;
using Crypto.Utils;

namespace Crypto.TLS.State
{
    public abstract class ReadingState : IState
    {
        public abstract ConnectionState State { get; }

        protected readonly IServiceProvider ServiceProvider;
        protected readonly Connection Connection;

        protected ReadingState(IServiceProvider serviceProvider, Connection connection)
        {
            ServiceProvider = serviceProvider;
            Connection = connection;
        }

        public IState Run()
        {
            while (true)
            {
                var record = Connection.ReadRecord();
                var result = HandleRecord(record);

                if (result.HasValue)
                {
                    return result.Value;
                }
            }

        }

        protected abstract Option<IState> HandleRecord(Record record);

        protected Option<IState> UnexpectedMessage()
        {
            var alertMessage = new AlertMessage(AlertLevel.Fatal, AlertDescription.UnexpectedMessage);
            
            return Option.Some<IState>(CloseConnectionWithAlertState.New(ServiceProvider, alertMessage));
        }
    }
}
