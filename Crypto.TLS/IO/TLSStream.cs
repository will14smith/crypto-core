using System;
using System.IO;
using System.Threading;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Alerts;
using Crypto.TLS.Records;
using Crypto.TLS.State;
using Crypto.TLS.State.Client;
using Crypto.TLS.State.Server;
using Crypto.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.IO
{
    public class TLSStream : Stream
    {
        private readonly Stream _inner;
        private readonly IServiceScope _servicesScope;

        private IServiceProvider Services => _servicesScope.ServiceProvider;

        private volatile bool _active;
        private Thread? _reader;
        private readonly ByteQueue _readQueue = new ByteQueue();

        public TLSStream(Stream inner, IServiceProvider services)
        {
            SecurityAssert.NotNull(inner);
            SecurityAssert.NotNull(services);

            _inner = inner;

            _servicesScope = services.CreateScope();
            Services.GetRequiredService<IStreamAccessor>().Stream = _inner;
        }

        public void AuthenticateAsServer()
        {
            Authenticate<InitialServerState>();
        }

        public void AuthenticateAsClient()
        {
            Authenticate<InitialClientState>();
        }

        private void Authenticate<TInitialState>()
            where TInitialState : IState
        {
            IState state = Services.GetRequiredService<TInitialState>();
            while (true)
            {
                Console.WriteLine("In state " + state.State);
                state = state.Run() ?? throw new InvalidOperationException($"State transitioned to null, previous state was {state.GetType()}");

                if (state is ActiveState)
                {
                    _active = true;

                    StartReadThread();
                    break;
                }

                if (state is CloseConnectionWithAlertState alertState)
                {
                    _inner.Close();
                    throw new UnableToEstablishSecureConnectionException(alertState.AlertMessage);
                }
            }
        }

        private void StartReadThread()
        {
            _reader = new Thread(ReadThread);
            _reader.Start();
        }
        private void ReadThread()
        {
            try
            {
                while (_active)
                {
                    var connection = Services.GetRequiredService<Connection>();
                    var record = connection.ReadRecord();

                    switch (record.Type)
                    {
                        case RecordType.Application:
                            _readQueue.Put(record.Data);
                            break;
                        
                        case RecordType.Alert:
                            HandleAlert(record);
                            break;
                        
                        // TODO handle alerts
                        default:
                            // TODO terminate connection
                            throw new InvalidOperationException();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
                // TODO handle error and close stuff
            }

            _active = false;
        }

        private void HandleAlert(Record record)
        {
            var alert = AlertMessage.Read(record.Data);

            if (alert.Level == AlertLevel.Warning && alert.Description == AlertDescription.CloseNotify)
            {
                var versionConfig = Services.GetRequiredService<VersionConfig>();
                var closeAlert = new AlertMessage(AlertLevel.Warning, AlertDescription.CloseNotify);
                var closeRecord = new Record(RecordType.Alert, versionConfig.Version, closeAlert.GetBytes());

                var connection = Services.GetRequiredService<Connection>();
                connection.WriteRecord(closeRecord);
                
                throw new Exception("Closing connection");
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            SecurityAssert.Assert(_active);
            
            var data = _readQueue.Take(count);
            Array.Copy(data, 0, buffer, offset, data.Length);

            return data.Length;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            SecurityAssert.Assert(_active);
            SecurityAssert.AssertBuffer(buffer, offset, count);

            var data = new byte[count];
            Array.Copy(buffer, offset, data, 0, count);

            var versionConfig = Services.GetRequiredService<VersionConfig>();
            var record = new Record(RecordType.Application, versionConfig.Version, data);

            var connection = Services.GetRequiredService<Connection>();
            connection.WriteRecord(record);
        }

        public override void Flush()
        {
            _inner.Flush();
        }

        public override bool CanRead => true;
        public override bool CanWrite => true;

        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Close()
        {
            // TODO close TLS connection
            _reader?.Abort();
            base.Close();
        }

        protected override void Dispose(bool disposing)
        {
            // TODO close TLS connection if open
            _servicesScope.Dispose();
        }
    }
}
