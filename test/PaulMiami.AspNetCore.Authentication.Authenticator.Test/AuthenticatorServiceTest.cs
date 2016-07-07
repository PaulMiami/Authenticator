#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Xunit;
using System.Text;
using Microsoft.Extensions.Options;
using System;
using System.Security.Cryptography;
using Moq;

namespace PaulMiami.AspNetCore.Authentication.Authenticator.Test
{
    public class AuthenticatorServiceTest
    {
        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
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
            Assert.Throws<ArgumentNullException>(()=> new AuthenticatorService(null, new DefaultSystemTime()));
        }

        [Fact]
        public void Success()
        {
            var options = GetOptions();

            var service = new AuthenticatorService(options, new DefaultSystemTime());
        }

        [Fact]
        public void MissingIssuer()
        {
            var options = GetOptions();
            options.Value.Issuer = null;

            var ex = Assert.Throws<ArgumentException>(() => new AuthenticatorService(options, new DefaultSystemTime()));
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
            var service = new AuthenticatorService(options, new DefaultSystemTime());
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
            var service = new AuthenticatorService(options, new DefaultSystemTime());

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
            var service = new AuthenticatorService(options, new DefaultSystemTime());

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
            var service = new AuthenticatorService(options, new DefaultSystemTime());

            var ex = Assert.Throws<ArgumentException>(() => service.GetUri(id, secret));
        }


        [Theory]
        [InlineData(59, 94287082, HashAlgorithm.SHA1, "12345678901234567890")]
        [InlineData(59, 46119246, HashAlgorithm.SHA256, "12345678901234567890123456789012")]
        [InlineData(59, 90693936, HashAlgorithm.SHA512, "1234567890123456789012345678901234567890123456789012345678901234")]
        [InlineData(1111111109, 07081804, HashAlgorithm.SHA1, "12345678901234567890")]
        [InlineData(1111111109, 68084774, HashAlgorithm.SHA256, "12345678901234567890123456789012")]
        [InlineData(1111111109, 25091201, HashAlgorithm.SHA512, "1234567890123456789012345678901234567890123456789012345678901234")]
        [InlineData(1111111111, 14050471, HashAlgorithm.SHA1, "12345678901234567890")]
        [InlineData(1111111111, 67062674, HashAlgorithm.SHA256, "12345678901234567890123456789012")]
        [InlineData(1111111111, 99943326, HashAlgorithm.SHA512, "1234567890123456789012345678901234567890123456789012345678901234")]
        [InlineData(1234567890, 89005924, HashAlgorithm.SHA1, "12345678901234567890")]
        [InlineData(1234567890, 91819424, HashAlgorithm.SHA256, "12345678901234567890123456789012")]
        [InlineData(1234567890, 93441116, HashAlgorithm.SHA512, "1234567890123456789012345678901234567890123456789012345678901234")]
        [InlineData(2000000000, 69279037, HashAlgorithm.SHA1, "12345678901234567890")]
        [InlineData(2000000000, 90698825, HashAlgorithm.SHA256, "12345678901234567890123456789012")]
        [InlineData(2000000000, 38618901, HashAlgorithm.SHA512, "1234567890123456789012345678901234567890123456789012345678901234")]
        [InlineData(20000000000, 65353130, HashAlgorithm.SHA1, "12345678901234567890")]
        [InlineData(20000000000, 77737706, HashAlgorithm.SHA256, "12345678901234567890123456789012")]
        [InlineData(20000000000, 47863826, HashAlgorithm.SHA512, "1234567890123456789012345678901234567890123456789012345678901234")]
        public void GetCodeTest(long time, int expectedCode, HashAlgorithm hashAlgorithm, string secret)
        {
            //https://tools.ietf.org/html/rfc6238#appendix-B

            var systemTime = new Mock<ISystemTime>(MockBehavior.Strict);
            systemTime
                .Setup(a => a.GetUtcNow())
                .Returns(UnixEpoch.AddSeconds(time))
                .Verifiable();

            var options = GetOptions();
            var service = new AuthenticatorService(options, systemTime.Object);
            var code = service.GetCode(hashAlgorithm, Encoding.UTF8.GetBytes(secret), 8, 30);
            Assert.Equal(expectedCode, code);

            systemTime.Verify();
        }

        [Fact]
        public void GetCodeBadHashAlgotithm()
        {
            var options = GetOptions();
            var service = new AuthenticatorService(options, new DefaultSystemTime());
            Assert.Throws<ArgumentException>(()=> service.GetCode((HashAlgorithm)10000, Encoding.UTF8.GetBytes("test"), 8, 30));
        }
    }
}
