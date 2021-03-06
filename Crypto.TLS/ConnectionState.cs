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
        WaitingForServerHello,
        RecievedServerHello,
        WaitingForServerHelloFollowup,
        RecievedServerCertificate,
        WaitingForServerCertificateFollowup,
        RecievedServerKeyExchange,
        WaitingForServerKeyExchangeFollowup,
        RecievedServerCertificateRequest,
        WaitingForServerCertificateRequestFollowup,
        RecievedServerHelloDone,
        WaitingForServerChangeCipherSpec,
        WaitingForServerFinished,
        RecievedServerFinished,
    }
}