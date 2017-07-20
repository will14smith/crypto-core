using System.Numerics;

namespace Crypto.TLS.DH
{
    public static class DHCalculator
    {
        public static BigInteger Calculate(BigInteger @base, BigInteger key, BigInteger prime)
        {
            return BigInteger.ModPow(@base, key, prime);
        }
    }
}
