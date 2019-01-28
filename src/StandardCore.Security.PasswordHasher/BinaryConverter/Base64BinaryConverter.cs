using System;

namespace StandardCore.Security.PasswordHasher.BinaryConverter
{
    public sealed class Base64BinaryConverter : IBinaryConverter
    {
        public byte[] GetBytes(string input) => Convert.FromBase64String(input);

        public string GetString(byte[] input) => Convert.ToBase64String(input);
    }
}
