namespace StandardCore.Security.PasswordHasher
{
    public interface ISecureRandomGenerator
    {
        byte[] GenerateBytes(uint length);
    }
}
