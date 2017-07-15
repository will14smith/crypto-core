namespace Crypto.Core.Randomness
{
    public interface IRandom
    {
        int RandomInt(int min, int max);
        byte[] RandomBytes(int length);
    }
}
