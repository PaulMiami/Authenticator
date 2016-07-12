#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PaulMiami.AspNetCore.Authentication.Authenticator;
using System;
using System.Linq;

namespace PaulMiami.AspNetCore.Identity.Authenticator
{
    public static class IdentityBuilderExtensions
    {
        public static IdentityBuilder AddAuthenticator(this IdentityBuilder builder, AuthenticatorServiceOptions configureOptions)
        {
            builder.Services.AddAuthenticator(configureOptions);
            builder.AddAuthenticator();
            return builder;
        }

        public static IdentityBuilder AddAuthenticator(this IdentityBuilder builder, Action<AuthenticatorServiceOptions> configuration)
        {
            builder.Services.AddAuthenticator(configuration);
            builder.AddAuthenticator();
            return builder;
        }

        private static void AddAuthenticator(this IdentityBuilder builder)
        {
            var userManagerType = typeof(UserManager<>).MakeGenericType(builder.UserType);
            var authenticatorUserManagerType = typeof(AuthenticatorUserManager<>).MakeGenericType(builder.UserType);

            builder.Services.Remove(builder.Services.Where(s => 
                s.ServiceType == userManagerType
                && s.Lifetime == ServiceLifetime.Scoped).FirstOrDefault());

            builder.Services.TryAddScoped(authenticatorUserManagerType, authenticatorUserManagerType);
            builder.Services.TryAddScoped(userManagerType, s => s.GetService(authenticatorUserManagerType));

            builder.AddTokenProvider("Authenticator", typeof(AuthenticatorTokenProvider<>).MakeGenericType(builder.UserType));
        }
    }
}
