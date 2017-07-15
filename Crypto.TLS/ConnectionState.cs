namespace Crypto.TLS
{
    public enum ConnectionState
    {
        Initial,
        Active,
        UnexpectedError,

        // server
        WaitingForClientHello,
        RecievedClientHello,
        SendingServerHello,
        SentServerHello,
        RecievedClientKeyExchange,
        WaitingForClientChangeCipherSpec,
        WaitingForClientFinished,
        RecievedClientFinished,
        
        // client
        SendingClientHello,
        WaitingForServerHello
    }
}