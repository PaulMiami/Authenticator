#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using System;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using PaulMiami.AspNetCore.Authentication.Authenticator;

namespace PaulMiami.AspNetCore.Identity.Authenticator.EntityFrameworkCore
{
    public class AuthenticatorUser : AuthenticatorUser<string>
    {
        public AuthenticatorUser()
        {
            Id = Guid.NewGuid().ToString();
        }

        public AuthenticatorUser(string userName) : this()
        {
            UserName = userName;
        }
    }

    public class AuthenticatorUser<TKey> : IdentityUser<TKey> 
        where TKey : IEquatable<TKey>
    {
        public string AuthenticatorSecretEncrypted { get; set; }

        public byte AuthenticatorNumberOfDigits { get; set; }

        public byte AuthenticatorPeriodInSeconds { get; set; }

        public HashAlgorithmType AuthenticatorHashAlgorithm { get; set; }
    }
}
