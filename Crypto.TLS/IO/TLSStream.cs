using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Alerts;
using Crypto.TLS.Records;
using Crypto.TLS.State;
using Crypto.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.IO
{
    public class TLSStream : Stream
    {
        private readonly Stream _inner;
        private readonly IServiceScope _servicesScope;

        private IServiceProvider Services => _servicesScope.ServiceProvider;

        private bool _active;
        private Thread _reader;
        private readonly CancellationTokenSource cts = new CancellationTokenSource();
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
                state = state.Run();

                if (state is ActiveState)
                {
                    _active = true;

                    StartReadThread();
                    break;
                }

                if (state is CloseConnectionWithAlertState alertState)
                {
                    WriteAlert(alertState.AlertMessage.Level, alertState.AlertMessage.Description);
                    Close();
                    throw new UnableToEstablishSecureConnectionException(alertState.AlertMessage);
                }
            }
        }

        private void StartReadThread()
        {
            _reader = new Thread(ReadThread);
            _reader.Start(cts.Token);
        }

        private void ReadThread(object parameter)
        {
            var token = (CancellationToken) parameter;

            while (!token.IsCancellationRequested)
            {
                var connection = Services.GetRequiredService<Connection>();
                Record record;

                try
                {
                    record = connection.ReadRecord();
                }
                catch
                {
                    InternalClose();
                    return;
                }

                switch (record.Type)
                {
                    case RecordType.Application:
                        _readQueue.Put(record.Data);
                        break;
                    case RecordType.Alert:
                        if (record.Data.Span[0] == 0x01 && record.Data.Span[1] == 0x00)
                        {
                            InternalClose();
                            return;
                        }
                        break;
                    default:
                        // TODO terminate connection
                        throw new InvalidOperationException();
                }
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            SecurityAssert.Assert(_active);

            var data = _readQueue.Take(count);
            data.CopyTo(buffer.AsSpan(offset));

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
            // TODO other actions?
            WriteAlert(AlertLevel.Warning, AlertDescription.CloseNotify);

            InternalClose();
        }

        private void InternalClose()
        {
            cts.Cancel();

            _active = false;

            _inner.Close();
            base.Close();
        }

        private void WriteAlert(AlertLevel level, AlertDescription description)
        {
            var data = new[] {(byte) level, (byte) description};

            var versionConfig = Services.GetRequiredService<VersionConfig>();
            var record = new Record(RecordType.Alert, versionConfig.Version, data);

            Services.GetRequiredService<Connection>().WriteRecord(record);
        }

        protected override void Dispose(bool disposing)
        {
            // TODO close TLS connection if open
            // TODO _servicesScope.Dispose();
        }
    }
}
