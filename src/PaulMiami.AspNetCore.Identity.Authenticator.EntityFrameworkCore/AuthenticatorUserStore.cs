#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PaulMiami.AspNetCore.Authentication.Authenticator;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace PaulMiami.AspNetCore.Identity.Authenticator.EntityFrameworkCore
{
    public class AuthenticatorUserStore : AuthenticatorUserStore<AuthenticatorUser<string>>
    {
        public AuthenticatorUserStore(DbContext context, IdentityErrorDescriber describer = null) 
            : base(context, describer) { }
    }

    public class AuthenticatorUserStore<TUser> : AuthenticatorUserStore<TUser, IdentityRole, DbContext, string>
        where TUser : AuthenticatorUser<string>, new()
    {
        public AuthenticatorUserStore(DbContext context, IdentityErrorDescriber describer = null) 
            : base(context, describer) { }
    }

    public class AuthenticatorUserStore<TUser, TRole, TContext> : AuthenticatorUserStore<TUser, TRole, TContext, string>
        where TUser : AuthenticatorUser<string>
        where TRole : IdentityRole<string>
        where TContext : DbContext
    {
        public AuthenticatorUserStore(TContext context, IdentityErrorDescriber describer = null) 
            : base(context, describer) { }
    }

    public class AuthenticatorUserStore<TUser, TRole, TContext, TKey> : UserStore<TUser, TRole, TContext, TKey>, IUserAuthenticatorStore<TUser>
        where TUser : AuthenticatorUser<TKey>
        where TRole : IdentityRole<TKey>
        where TContext : DbContext
        where TKey : IEquatable<TKey>
    {
        public AuthenticatorUserStore(TContext context, IdentityErrorDescriber describer = null) 
            : base(context, describer) { }

        public virtual Task<AuthenticatorParams> GetAuthenticatorParamsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            user.CheckArgumentNull(nameof(user));

            var authenticatorParams = new AuthenticatorParams();
            if (!string.IsNullOrEmpty(user.AuthenticatorSecretEncrypted))
                authenticatorParams.Secret = Convert.FromBase64String(user.AuthenticatorSecretEncrypted);
            else
                authenticatorParams.Secret = null;
            authenticatorParams.HashAlgorithm = user.AuthenticatorHashAlgorithm;
            authenticatorParams.NumberOfDigits = user.AuthenticatorNumberOfDigits;
            authenticatorParams.PeriodInSeconds = user.AuthenticatorPeriodInSeconds;

            return Task.FromResult(authenticatorParams);
        }

        public virtual Task SetAuthenticatorParamsAsync(TUser user, AuthenticatorParams authenticatorParams, CancellationToken cancellationToken = default(CancellationToken))
        {

            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            user.CheckArgumentNull(nameof(user));
            authenticatorParams.CheckArgumentNull(nameof(authenticatorParams));

            if (authenticatorParams.Secret != null)
                user.AuthenticatorSecretEncrypted = Convert.ToBase64String(authenticatorParams.Secret);
            else
                user.AuthenticatorSecretEncrypted = null;
            user.AuthenticatorHashAlgorithm = authenticatorParams.HashAlgorithm;
            user.AuthenticatorNumberOfDigits = authenticatorParams.NumberOfDigits;
            user.AuthenticatorPeriodInSeconds = authenticatorParams.PeriodInSeconds;

            return Task.FromResult(0);
        }
    }
}
