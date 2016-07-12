#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Microsoft.AspNetCore.Identity;
using PaulMiami.AspNetCore.Authentication.Authenticator;
using System;
using System.Threading.Tasks;

namespace PaulMiami.AspNetCore.Identity.Authenticator
{
    public class AuthenticatorTokenProvider<TUser> : IUserTwoFactorTokenProvider<TUser> where TUser : class
    {
        private IAuthenticatorService _authenticationService;

        public AuthenticatorTokenProvider(IAuthenticatorService authenticationService)
        {
            authenticationService.CheckArgumentNull(nameof(authenticationService));

            _authenticationService = authenticationService;
        }

        public async Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
        {
            return await GetAuthenticatorUserManager(manager).GetAuthenticatorEnabledAsync(user);
        }

        public Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
        {
            throw new InvalidOperationException();
        }

        public async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
        {
            int code;
            if (!token.TryParseAndRemoveWhiteSpace(out code))
            {
                return false;
            }

            var authenticatorParams = await GetAuthenticatorUserManager(manager).GetAuthenticatorParamsAsync(user);
            var execpectedCode = _authenticationService.GetCode(
                authenticatorParams.HashAlgorithm, 
                authenticatorParams.Secret, 
                authenticatorParams.NumberOfDigits, 
                authenticatorParams.PeriodInSeconds);

            return code == execpectedCode;
        }

        private AuthenticatorUserManager<TUser> GetAuthenticatorUserManager(UserManager<TUser> manager)
        {
            var cast = manager as AuthenticatorUserManager<TUser>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.UserManagerBadCast);
            }
            return cast;
        }
    }
}
