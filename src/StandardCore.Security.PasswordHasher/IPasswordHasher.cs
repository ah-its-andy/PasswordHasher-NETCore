namespace StandardCore.Security.PasswordHasher
{
    public interface IPasswordHasher
    {
        string HashPassword(string password);
        string HashPassword(string password, byte formatMarker);

        bool VerifyHashedPassword(string hashedPassword, string providedPassword);
    }
}
