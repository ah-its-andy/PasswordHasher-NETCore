using System.Security.Cryptography;

namespace StandardCore.Security.PasswordHasher
{
    public interface IPasswordFormatHasher
    {
        bool Supported(byte formatMarker);

        byte[] HashPassword(string password, ISecureRandomGenerator secureRandomGenerator);
        bool VerifyHashedPassword(byte[] decodedHashedPassword, string providedPassword);
    }
}
