#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

namespace PaulMiami.AspNetCore.Authentication.Authenticator
{
    public class AuthenticatorServiceOptions
    {
        public string Issuer { get; set; }

        public HashAlgorithm HashAlgorithm { get; set; } = HashAlgorithm.SHA1;

        public byte NumberOfDigits { get; set; } = 6;

        public byte PeriodInSeconds { get; set; } = 30;
    }
}
