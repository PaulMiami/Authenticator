#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Xunit;
using System.Text;
using System.Linq;
using Microsoft.Extensions.Options;
using System;
using System.Security.Cryptography;

namespace PaulMiami.AspNetCore.Authentication.Authenticator.Test
{
    public class AuthenticatorServiceTest
    {
        private readonly string Issuer = Guid.NewGuid().ToString();

        public IOptions<AuthenticatorServiceOptions> GetOptions()
        {
            return new OptionsWrapper<AuthenticatorServiceOptions>(new AuthenticatorServiceOptions
            {
                Issuer = Issuer
            });
        }

        [Fact]
        public void NullOptions()
        {
            Assert.Throws<ArgumentNullException>(()=> new AuthenticatorService(null));
        }

        [Fact]
        public void Success()
        {
            var options = GetOptions();

            var service = new AuthenticatorService(options);
        }

        [Fact]
        public void MissingIssuer()
        {
            var options = GetOptions();
            options.Value.Issuer = null;

            var ex = Assert.Throws<ArgumentException>(() => new AuthenticatorService(options));
            Assert.Equal("The 'Issuer' option must be provided.", ex.Message);
        }

        [Theory]
        [InlineData(HashAlgorithm.SHA1, 10, 5)]
        [InlineData(HashAlgorithm.SHA256, 20, 8)]
        [InlineData(HashAlgorithm.SHA512, 35, 9)]
        public void GetUriSuccess(HashAlgorithm hashAlgorithm, int period, int digits)
        {
            var id = Guid.NewGuid().ToString();
            var secret = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(secret);
            }

            var options = GetOptions();
            options.Value.HashAlgorithm = hashAlgorithm;
            options.Value.NumberOfDigits = digits;
            options.Value.PeriodInSeconds = period;
            var service = new AuthenticatorService(options);
            var uri = service.GetUri(id, secret);

            Assert.Equal(string.Format("otpauth://totp/{0}%3A{1}?secret={2}&issuer={0}&algorithm={3}&digits={4}&period={5}", 
                Issuer, 
                id, 
                Base32Encoding.Encode(secret).Trim('='),
                hashAlgorithm.ToString(),
                digits,
                period
                ), uri);
        }

        [Fact]
        public void GetUriNullSecret()
        {
            var id = Guid.NewGuid().ToString();
            byte[] secret = null;

            var options = GetOptions();
            var service = new AuthenticatorService(options);

            var ex = Assert.Throws<ArgumentNullException>(()=> service.GetUri(id, secret));
        }

        [Fact]
        public void GetUriNullUserId()
        {
            var secret = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(secret);
            }

            var options = GetOptions();
            var service = new AuthenticatorService(options);

            var ex = Assert.Throws<ArgumentNullException>(() => service.GetUri(null, secret));
        }

        [Fact]
        public void GetUriNullBadHashAlgotithm()
        {
            var id = Guid.NewGuid().ToString();
            var secret = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(secret);
            }

            var options = GetOptions();
            options.Value.HashAlgorithm = (HashAlgorithm)10000;
            var service = new AuthenticatorService(options);

            var ex = Assert.Throws<ArgumentException>(() => service.GetUri(id, secret));
        }
    }
}
