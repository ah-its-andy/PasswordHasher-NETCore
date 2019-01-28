using Microsoft.AspNetCore.Identity;
using System;
using IStandardCoreHasher = StandardCore.Security.PasswordHasher.IPasswordHasher;

namespace StandardCore.Security.PasswordHasher.Identity
{
    public class PasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
    {
        private readonly IStandardCoreHasher _passwordHasher;

        public PasswordHasher(IStandardCoreHasher passwordHasher)
        {
            _passwordHasher = passwordHasher ?? throw new ArgumentNullException(nameof(passwordHasher));
        }

        public string HashPassword(TUser user, string password)
            => _passwordHasher.HashPassword(password);

        public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
            => _passwordHasher.VerifyHashedPassword(hashedPassword, providedPassword) ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
    }
}
