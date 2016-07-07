#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using System;
using System.Globalization;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Options;

namespace PaulMiami.AspNetCore.Authentication.Authenticator
{
    public class AuthenticatorService
    {
        private AuthenticatorServiceOptions _options;

        public AuthenticatorService(IOptions<AuthenticatorServiceOptions> options)
        {
            options.CheckArgumentNull(nameof(options));

            options.Value.Issuer.CheckMandatoryOption(nameof(options.Value.Issuer));

            _options = options.Value;
        }

        public string GetUri(string userIdentifier, byte[] secret)
        {
            userIdentifier.CheckArgumentNullOrEmpty(nameof(userIdentifier));

            if (secret == null || secret.Length == 0)
                throw new ArgumentNullException(nameof(secret));

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
