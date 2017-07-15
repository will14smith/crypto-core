namespace Crypto.TLS.State
{
    public interface IState
    {
        ConnectionState State { get; }

        IState Run();
    }
}