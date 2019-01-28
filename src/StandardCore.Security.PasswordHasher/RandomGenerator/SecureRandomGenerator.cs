using System.Security.Cryptography;

namespace StandardCore.Security.PasswordHasher.RandomGenerator
{
    public class SecureRandomGenerator : ISecureRandomGenerator
    {
        private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        
        public byte[] GenerateBytes(uint length)
        {
            var bytes = new byte[length];
            _rng.GetBytes(bytes);
            return bytes;
        }
    }
}
