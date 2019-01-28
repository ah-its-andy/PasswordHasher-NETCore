using System;
using System.Collections.Generic;
using System.Linq;

namespace StandardCore.Security.PasswordHasher
{
    public class PasswordHasher : IPasswordHasher
    {
        private readonly IBinaryConverter _binaryConverter;
        private readonly ISecureRandomGenerator _secureRandomGenerator;
        private readonly IEnumerable<IPasswordFormatHasher> _passwordFormatHashers;

        public PasswordHasher(IBinaryConverter binaryConverter, ISecureRandomGenerator secureRandomGenerator, IEnumerable<IPasswordFormatHasher> passwordFormatHashers)
        {
            _binaryConverter = binaryConverter ?? throw new ArgumentNullException(nameof(binaryConverter));
            _secureRandomGenerator = secureRandomGenerator ?? throw new ArgumentNullException(nameof(secureRandomGenerator));
            _passwordFormatHashers = passwordFormatHashers ?? throw new ArgumentNullException(nameof(passwordFormatHashers));
        }

        public string HashPassword(string password)
        {
            return HashPassword(password, FormatMarkers.Pbkdf2);
        }

        public string HashPassword(string password, byte formatMarker)
        {           
            var hashedPassword = GetPasswordFormatHasher(formatMarker).HashPassword(password, _secureRandomGenerator);
            return _binaryConverter.GetString(hashedPassword);
        }

        public bool VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            var decodedHashedPassword = _binaryConverter.GetBytes(hashedPassword);
            var formatMarker = decodedHashedPassword[0];
            return GetPasswordFormatHasher(formatMarker).VerifyHashedPassword(decodedHashedPassword, providedPassword);
        }

        private IPasswordFormatHasher GetPasswordFormatHasher(byte formatMarker)
        {
            var passwordFormatHasher = _passwordFormatHashers.FirstOrDefault(x => x.Supported(formatMarker));
            if (passwordFormatHasher == null) throw new NotSupportedException($"Format marker {formatMarker}");
            return passwordFormatHasher;
        }
    }
}
