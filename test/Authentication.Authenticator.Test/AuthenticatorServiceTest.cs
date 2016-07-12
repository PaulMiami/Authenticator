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
        [InlineData(HashAlgorithmType.SHA1, 30, 6)]
        [InlineData(HashAlgorithmType.SHA256, 60, 8)]
        [InlineData(HashAlgorithmType.SHA512, 200, 7)]
        public void GetUriSuccess(HashAlgorithmType hashAlgorithm, byte period,  byte digits)
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
            options.Value.HashAlgorithm = (HashAlgorithmType)100;
            var service = new AuthenticatorService(options, new DefaultSystemTime());

            var ex = Assert.Throws<ArgumentException>(() => service.GetUri(id, secret));
        }


        [Theory]
        [InlineData(59, 94287082, HashAlgorithmType.SHA1, "12345678901234567890")]
        [InlineData(59, 46119246, HashAlgorithmType.SHA256, "12345678901234567890123456789012")]
        [InlineData(59, 90693936, HashAlgorithmType.SHA512, "1234567890123456789012345678901234567890123456789012345678901234")]
        [InlineData(1111111109, 07081804, HashAlgorithmType.SHA1, "12345678901234567890")]
        [InlineData(1111111109, 68084774, HashAlgorithmType.SHA256, "12345678901234567890123456789012")]
        [InlineData(1111111109, 25091201, HashAlgorithmType.SHA512, "1234567890123456789012345678901234567890123456789012345678901234")]
        [InlineData(1111111111, 14050471, HashAlgorithmType.SHA1, "12345678901234567890")]
        [InlineData(1111111111, 67062674, HashAlgorithmType.SHA256, "12345678901234567890123456789012")]
        [InlineData(1111111111, 99943326, HashAlgorithmType.SHA512, "1234567890123456789012345678901234567890123456789012345678901234")]
        [InlineData(1234567890, 89005924, HashAlgorithmType.SHA1, "12345678901234567890")]
        [InlineData(1234567890, 91819424, HashAlgorithmType.SHA256, "12345678901234567890123456789012")]
        [InlineData(1234567890, 93441116, HashAlgorithmType.SHA512, "1234567890123456789012345678901234567890123456789012345678901234")]
        [InlineData(2000000000, 69279037, HashAlgorithmType.SHA1, "12345678901234567890")]
        [InlineData(2000000000, 90698825, HashAlgorithmType.SHA256, "12345678901234567890123456789012")]
        [InlineData(2000000000, 38618901, HashAlgorithmType.SHA512, "1234567890123456789012345678901234567890123456789012345678901234")]
        [InlineData(20000000000, 65353130, HashAlgorithmType.SHA1, "12345678901234567890")]
        [InlineData(20000000000, 77737706, HashAlgorithmType.SHA256, "12345678901234567890123456789012")]
        [InlineData(20000000000, 47863826, HashAlgorithmType.SHA512, "1234567890123456789012345678901234567890123456789012345678901234")]
        public void GetCodeTest(long time, int expectedCode, HashAlgorithmType hashAlgorithm, string secret)
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
            Assert.Throws<ArgumentException>(()=> service.GetCode((HashAlgorithmType)100, Encoding.UTF8.GetBytes("test"), 8, 30));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(5)]
        [InlineData(9)]
        [InlineData(10)]
        public void InvalidNumberOfDigits(byte numberOfDigit)
        {
            var options = GetOptions();
            options.Value.NumberOfDigits = numberOfDigit;

            var ex = Assert.Throws<ArgumentException>(() => new AuthenticatorService(options, new DefaultSystemTime()));
            Assert.Equal("The number of digits must be between 6 and 8.", ex.Message);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(29)]
        public void InvalidPeriodInSeconds(byte periodInSeconds)
        {
            var options = GetOptions();
            options.Value.PeriodInSeconds = periodInSeconds;

            var ex = Assert.Throws<ArgumentException>(() => new AuthenticatorService(options, new DefaultSystemTime()));
            Assert.Equal("The period must be at least 30 seconds.", ex.Message);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(5)]
        [InlineData(9)]
        [InlineData(10)]
        public void GetCodeInvalidNumberOfDigits(byte numberOfDigit)
        {
            var options = GetOptions();
            var service = new AuthenticatorService(options, new DefaultSystemTime());

            var ex = Assert.Throws<ArgumentException>(() => service.GetCode(HashAlgorithmType.SHA1, Encoding.UTF8.GetBytes("12345678901234567890"), numberOfDigit, 30));
            Assert.Equal("The number of digits must be between 6 and 8.", ex.Message);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(5)]
        [InlineData(9)]
        [InlineData(10)]
        public void GetCodeInvalidPeriodInSeconds(byte periodInSeconds)
        {
            var options = GetOptions();
            var service = new AuthenticatorService(options, new DefaultSystemTime());

            var ex = Assert.Throws<ArgumentException>(() => service.GetCode(HashAlgorithmType.SHA1, Encoding.UTF8.GetBytes("12345678901234567890"), 6, periodInSeconds));
            Assert.Equal("The period must be at least 30 seconds.", ex.Message);
        }


        [Theory]
        [InlineData(HashAlgorithmType.SHA1)]
        [InlineData(HashAlgorithmType.SHA256)]
        [InlineData(HashAlgorithmType.SHA512)]
        public void GetHashAlgorithm(HashAlgorithmType hashAlgorithm)
        {
            var options = GetOptions();
            options.Value.HashAlgorithm = hashAlgorithm;

            var service = new AuthenticatorService(options, new DefaultSystemTime());

            Assert.Equal(hashAlgorithm, service.HashAlgorithm);
        }

        [Theory]
        [InlineData(6)]
        [InlineData(7)]
        [InlineData(8)]
        public void GetNumberOfDigits(byte numberOfDigits)
        {
            var options = GetOptions();
            options.Value.NumberOfDigits = numberOfDigits;

            var service = new AuthenticatorService(options, new DefaultSystemTime());

            Assert.Equal(numberOfDigits, service.NumberOfDigits);
        }

        [Theory]
        [InlineData(30)]
        [InlineData(100)]
        [InlineData(150)]
        public void GetPeriodInSeconds(byte periodInSeconds)
        {
            var options = GetOptions();
            options.Value.PeriodInSeconds = periodInSeconds;

            var service = new AuthenticatorService(options, new DefaultSystemTime());

            Assert.Equal(periodInSeconds, service.PeriodInSeconds);
        }
    }
}
