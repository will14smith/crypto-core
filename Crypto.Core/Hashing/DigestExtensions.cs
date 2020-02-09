namespace Crypto.Core.Hashing
{
    public static class DigestExtensions
    {
        public static byte[] DigestBuffer(this IDigest digest)
        {
            var buffer = new byte[digest.HashSize / 8];
            digest.Digest(buffer);
            return buffer;
        }
    }
}