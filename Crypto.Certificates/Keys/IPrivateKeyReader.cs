namespace Crypto.Certificates.Keys
{
    public interface IPrivateKeyReader
    {
        PrivateKey ReadPrivateKey(X509AlgorithmIdentifier algorithm, byte[] input);
    }
}