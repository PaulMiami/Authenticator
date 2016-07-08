#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using System;
using System.Globalization;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace PaulMiami.AspNetCore.Authentication.Authenticator
{
    public class AuthenticatorService
    {
        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private static readonly int[] TenPow = new[] { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };
        private AuthenticatorServiceOptions _options;
        private ISystemTime _systemTime;

        public AuthenticatorService(IOptions<AuthenticatorServiceOptions> options, ISystemTime systemTime)
        {
            options.CheckArgumentNull(nameof(options));
            systemTime.CheckArgumentNull(nameof(systemTime));

            options.Value.Issuer.CheckMandatoryOption(nameof(options.Value.Issuer));

            if (options.Value.NumberOfDigits < 6 || options.Value.NumberOfDigits > 8)
                throw new ArgumentException(Resources.Exception_InvalidNumberOfDigits);

            if (options.Value.PeriodInSeconds < 30)
                throw new ArgumentException(Resources.Exception_InvalidPeriodInSeconds);

            _options = options.Value;
            _systemTime = systemTime;
        }

        public string GetUri(string userIdentifier, byte[] secret)
        {
            userIdentifier.CheckArgumentNullOrEmpty(nameof(userIdentifier));

            secret.CheckArgumentNullOrEmpty(nameof(secret));

            return string.Format(
                    CultureInfo.InvariantCulture,
                    "otpauth://totp/{0}{1}?secret={2}&issuer={3}&algorithm={4}&digits={5}&period={6}",
                    UrlEncoder.Default.Encode($"{_options.Issuer}:"),
                    UrlEncoder.Default.Encode(userIdentifier).Replace("@", "%40"),
                    Base32Encoding.Encode(secret).Trim('='),
                    UrlEncoder.Default.Encode(_options.Issuer),
                    GetHashAlgorithm(_options.HashAlgorithm),
                    _options.NumberOfDigits,
                    _options.PeriodInSeconds);
        }

        public int GetCode(HashAlgorithm hashAlgorithm, byte[] secret, byte numberOfDigits, byte periodInSeconds)
        {
            //https://tools.ietf.org/html/rfc4226#section-5.4
            //https://tools.ietf.org/html/rfc6238#section-4.2

            secret.CheckArgumentNullOrEmpty(nameof(secret));

            if (numberOfDigits < 6 || numberOfDigits > 8)
                throw new ArgumentException(Resources.Exception_InvalidNumberOfDigits);

            if (periodInSeconds < 30)
                throw new ArgumentException(Resources.Exception_InvalidPeriodInSeconds);

            var deltaTime = _systemTime.GetUtcNow() - UnixEpoch;
            var counter = ConvertToBytes((ulong)(deltaTime.TotalSeconds / periodInSeconds));
            byte[] hash;

            using (var hmacAlgorithm = GetHmac(hashAlgorithm))
            {
                hmacAlgorithm.Key = secret;
                hash = hmacAlgorithm.ComputeHash(counter);
            }

            int offset = hash[hash.Length-1] & 0xf;
            int code = (hash[offset] & 0x7f) << 24
               | (hash[offset + 1] & 0xff) << 16
               | (hash[offset + 2] & 0xff) << 8
               | (hash[offset + 3] & 0xff);

            return code % TenPow[numberOfDigits];
        }

        private byte[] ConvertToBytes(ulong input)
        {
            var result = new byte[8];
            var offset = 0;
            while (input != 0)
            {
                result[7 - offset] = (byte)(input & 0xFF);
                input >>= 8;
                offset++;
            }
            return result;
        }

        private HMAC GetHmac(HashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.SHA1:
                    return new HMACSHA1();
                case HashAlgorithm.SHA256:
                    return new HMACSHA256();
                case HashAlgorithm.SHA512:
                    return new HMACSHA512();
                default:
                    throw new ArgumentException(nameof(hashAlgorithm));
            }
        }

        private string GetHashAlgorithm(HashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.SHA1:
                    return "SHA1";
                case HashAlgorithm.SHA256:
                    return "SHA256";
                case HashAlgorithm.SHA512:
                    return "SHA512";
                default:
                    throw new ArgumentException(nameof(hashAlgorithm));
            }
        }
    }
}
