#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PaulMiami.AspNetCore.Authentication.Authenticator;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace PaulMiami.AspNetCore.Identity.Authenticator
{
    public class AuthenticatorUserManager<TUser> : UserManager<TUser> where TUser : class
    {
        private IAuthenticatorService _authenticatorService;
        private IDataProtector _dataProtector;

        public AuthenticatorUserManager(IUserStore<TUser> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<TUser> passwordHasher,
            IEnumerable<IUserValidator<TUser>> userValidators,
            IEnumerable<IPasswordValidator<TUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services, 
            ILogger<UserManager<TUser>> logger,
            IDataProtectionProvider dataProtectionProvider,
            IAuthenticatorService authenticatorService) 
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
            dataProtectionProvider.CheckArgumentNull(nameof(dataProtectionProvider));
            authenticatorService.CheckArgumentNull(nameof(authenticatorService));

            _authenticatorService = authenticatorService;
            _dataProtector = dataProtectionProvider.CreateProtector("AuthenticatorUserManager");
        }

        public virtual async Task<bool> GetAuthenticatorEnabledAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            var userAuthenticatorStore = GetUserAuthenticatorStore();
            user.CheckArgumentNull(nameof(user));

            return (await userAuthenticatorStore.GetAuthenticatorParamsAsync(user, cancellationToken)).Secret != null;
        }

        public virtual async Task<AuthenticatorParams> GetAuthenticatorParamsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            var userAuthenticatorStore = GetUserAuthenticatorStore();
            user.CheckArgumentNull(nameof(user));

            var authenticatorParams = await userAuthenticatorStore.GetAuthenticatorParamsAsync(user, cancellationToken);
            authenticatorParams.Secret = _dataProtector.Unprotect(authenticatorParams.Secret);

            return authenticatorParams;
        }

        public virtual async Task<bool> EnableAuthenticatorAsync(TUser user, Authenticator authenticator, string code, CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            var userAuthenticatorStore = GetUserAuthenticatorStore();
            user.CheckArgumentNull(nameof(user));
            authenticator.CheckArgumentNull(nameof(authenticator));

            var authenticatorEnabled = await GetAuthenticatorEnabledAsync(user, cancellationToken);
            if (authenticatorEnabled)
                throw new InvalidOperationException(Resources.Exception_AuthenticatorAlreadyEnableForThisUser);

            if (!ValidateAuthenticatorCode(code, authenticator.HashAlgorithm, authenticator.Secret, authenticator.NumberOfDigits, authenticator.PeriodInSeconds))
                return false;

            var authenticatorParams = new AuthenticatorParams
            {
                Secret = _dataProtector.Protect(authenticator.Secret),
                HashAlgorithm = authenticator.HashAlgorithm,
                NumberOfDigits = authenticator.NumberOfDigits,
                PeriodInSeconds = authenticator.PeriodInSeconds
            };

            await userAuthenticatorStore.SetAuthenticatorParamsAsync(user, authenticatorParams, cancellationToken);

            await UpdateAsync(user);
            return true;
        }

        public virtual async Task<bool> DisableAuthenticatorAsync(TUser user, string code, CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            var userAuthenticatorStore = GetUserAuthenticatorStore();
            user.CheckArgumentNull(nameof(user));

            var authenticatorParams = await GetAuthenticatorParamsAsync(user, cancellationToken);

            if (!ValidateAuthenticatorCode(code, authenticatorParams.HashAlgorithm, authenticatorParams.Secret, authenticatorParams.NumberOfDigits, authenticatorParams.PeriodInSeconds))
                return false;

            authenticatorParams = new AuthenticatorParams
            {
                Secret = null,
                HashAlgorithm = HashAlgorithmType.SHA1,
                NumberOfDigits = 0,
                PeriodInSeconds = 0
            };

            await userAuthenticatorStore.SetAuthenticatorParamsAsync(user, authenticatorParams, cancellationToken);

            await UpdateAsync(user);
            return true;
        }

        public virtual async Task<Authenticator> CreateAuthenticatorAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            var userAuthenticatorStore = GetUserAuthenticatorStore();
            user.CheckArgumentNull(nameof(user));

            var authenticatorEnabled = await GetAuthenticatorEnabledAsync(user, cancellationToken);
            if (authenticatorEnabled)
                throw new InvalidOperationException(Resources.Exception_AuthenticatorAlreadyEnableForThisUser);

            var email = await GetEmailAsync(user);
            var authenticator = new Authenticator();
            authenticator.HashAlgorithm = _authenticatorService.HashAlgorithm;
            authenticator.Secret = GenerateAuthenticatorSecret(authenticator.HashAlgorithm);
            authenticator.NumberOfDigits = _authenticatorService.NumberOfDigits;
            authenticator.PeriodInSeconds = _authenticatorService.PeriodInSeconds;
            authenticator.Uri = _authenticatorService.GetUri(email, authenticator.Secret);
            return authenticator;
        }

        private byte[] GenerateAuthenticatorSecret(HashAlgorithmType hashAlgorithm)
        {
            var keySize = 20;

            if (hashAlgorithm == HashAlgorithmType.SHA1)
                keySize = 20;
            else if (hashAlgorithm == HashAlgorithmType.SHA256)
                keySize = 32;
            else if (hashAlgorithm == HashAlgorithmType.SHA512)
                keySize = 64;
            else
                throw new ArgumentException(nameof(hashAlgorithm));

            var secret = new byte[keySize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(secret);
            }

            return secret;
        }

        private bool ValidateAuthenticatorCode(string code, HashAlgorithmType hashAlgorithm, byte[] secret, byte numberOfDigits, byte periodInSeconds)
        {
            int codeParsed;
            if (!code.TryParseAndRemoveWhiteSpace(out codeParsed))
            {
                return false;
            }

            var expectedCode = _authenticatorService.GetCode(hashAlgorithm, secret, numberOfDigits, periodInSeconds);
            return expectedCode == codeParsed;
        }

        private IUserAuthenticatorStore<TUser> GetUserAuthenticatorStore()
        {
            var cast = Store as IUserAuthenticatorStore<TUser>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserAuthenticatorStore);
            }
            return cast;
        }
    }
}
