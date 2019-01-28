using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace StandardCore.Security.PasswordHasher
{
    public class PasswordHasher : IPasswordHasher
    {
        private static readonly RandomNumberGenerator randomNumberGenerator;

        public string HashPassword(string password)
        {
            throw new NotImplementedException();
        }

        public string HashPassword(string password, byte formatMarker)
        {
            throw new NotImplementedException();
        }

        public bool VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            throw new NotImplementedException();
        }
    }
}
