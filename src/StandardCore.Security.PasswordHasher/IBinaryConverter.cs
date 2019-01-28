namespace StandardCore.Security.PasswordHasher
{
    public interface IBinaryConverter
    {
        string GetString(byte[] input);
        byte[] GetBytes(string input);
    }
}
