#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using PaulMiami.AspNetCore.Authentication.Authenticator;

namespace PaulMiami.AspNetCore.Identity.Authenticator
{
    public class AuthenticatorParams
    {
        public HashAlgorithmType HashAlgorithm { get; set;  }

        public byte[] Secret { get; set; }

        public byte NumberOfDigits { get; set; }

        public byte PeriodInSeconds { get; set; }
    }
}
