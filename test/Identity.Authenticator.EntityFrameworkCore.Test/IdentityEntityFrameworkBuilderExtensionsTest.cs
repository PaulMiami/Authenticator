#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Linq;
using Xunit;

namespace PaulMiami.AspNetCore.Identity.Authenticator.EntityFrameworkCore.Test
{
    public class IdentityEntityFrameworkBuilderExtensionsTest
    {
        [Fact]
        public void AddAuthenticatorEntityFrameworkStoreTest()
        {
            var userType = typeof(AuthenticatorUser);
            var roleType = typeof(IdentityRole);
            var services = new ServiceCollection();
            var builder = new IdentityBuilder(userType, roleType, services);

            services.AddScoped<IUserStore<AuthenticatorUser>, UserStore<AuthenticatorUser>>();

            builder.AddAuthenticatorEntityFrameworkStore<DbContext>();

            Assert.True(services.Where(serviceDescriptor =>
              serviceDescriptor.ServiceType == typeof(IUserStore<AuthenticatorUser>)
              && serviceDescriptor.Lifetime == ServiceLifetime.Scoped).Count() == 1);

            Assert.Equal(1, services.Count);
        }

        [Fact]
        public void AddAuthenticatorEntityFrameworkStoreIntTest()
        {
            var userType = typeof(AuthenticatorUser<int>);
            var roleType = typeof(IdentityRole<int>);
            var services = new ServiceCollection();
            var builder = new IdentityBuilder(userType, roleType, services);

            services.AddScoped<IUserStore<AuthenticatorUser<int>>, UserStore<AuthenticatorUser<int>, IdentityRole<int>, DbContext, int>>();

            builder.AddAuthenticatorEntityFrameworkStore<DbContext, int>();

            Assert.True(services.Where(serviceDescriptor =>
              serviceDescriptor.ServiceType == typeof(IUserStore<AuthenticatorUser<int>>)
              && serviceDescriptor.Lifetime == ServiceLifetime.Scoped).Count() == 1);

            Assert.Equal(1, services.Count);
        }
    }
}
