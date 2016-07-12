#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;

namespace PaulMiami.AspNetCore.Identity.Authenticator.EntityFrameworkCore
{
    public static class IdentityEntityFrameworkBuilderExtensions
    {
        public static IdentityBuilder AddAuthenticatorEntityFrameworkStore<TContext>(this IdentityBuilder builder)
            where TContext : DbContext
        {
            builder.AddDefaultServices(typeof(TContext));
            return builder;
        }
        
        public static IdentityBuilder AddAuthenticatorEntityFrameworkStore<TContext, TKey>(this IdentityBuilder builder)
            where TContext : DbContext
            where TKey : IEquatable<TKey>
        {
            builder.AddDefaultServices(typeof(TContext), typeof(TKey));
            return builder;
        }

        private static void AddDefaultServices(this IdentityBuilder builder, Type contextType, Type keyType = null)
        {
            var userStoreInterfaceType = typeof(IUserStore<>).MakeGenericType(builder.UserType);

            keyType = keyType ?? typeof(string);
            builder.Services.Remove(builder.Services.Where(s =>
                s.ServiceType == userStoreInterfaceType
                && s.Lifetime == ServiceLifetime.Scoped).FirstOrDefault());

            var userStoreType = typeof(AuthenticatorUserStore<,,,>).MakeGenericType(builder.UserType, builder.RoleType, contextType, keyType);

            builder.Services.AddScoped(userStoreInterfaceType, userStoreType);
        }
    }
}
