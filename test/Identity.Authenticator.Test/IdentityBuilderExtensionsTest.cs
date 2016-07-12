#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PaulMiami.AspNetCore.Authentication.Authenticator;
using PaulMiami.AspNetCore.Authentication.Authenticator.Test;
using System;
using System.Linq;
using Xunit;

namespace PaulMiami.AspNetCore.Identity.Authenticator.Test
{
    public class IdentityBuilderExtensionsTest
    {
        [Fact]
        public void NullOptions()
        {
            var userType = typeof(string);
            var roleType = typeof(string);
            var services = new ServiceCollection();
            var builder = new IdentityBuilder(userType, roleType, services);

            var authenticatorServiceOptions = new AuthenticatorServiceOptions();

            Assert.Throws<ArgumentNullException>(() => builder.AddAuthenticator((AuthenticatorServiceOptions)null));
        }

        [Fact]
        public void NullAction()
        {
            var userType = typeof(string);
            var roleType = typeof(string);
            var services = new ServiceCollection();
            var builder = new IdentityBuilder(userType, roleType, services);

            var authenticatorServiceOptions = new AuthenticatorServiceOptions();

            Assert.Throws<ArgumentNullException>(() => builder.AddAuthenticator((Action<AuthenticatorServiceOptions>)null));
        }

        [Fact]
        public void Success()
        {
            var userType = typeof(string);
            var roleType = typeof(string);
            var services = new ServiceCollection();
            var builder = new IdentityBuilder(userType, roleType, services);

            var userManagerType = typeof(UserManager<string>);
            services.AddScoped(userManagerType);

            var authenticatorServiceOptions = new AuthenticatorServiceOptions();

            var actualBuilder = builder.AddAuthenticator(authenticatorServiceOptions);

            AddAuthenticatorTest(builder, actualBuilder, services);
        }

        [Fact]
        public void SuccessAction()
        {
            var userType = typeof(string);
            var roleType = typeof(string);
            var services = new ServiceCollection();
            var builder = new IdentityBuilder(userType, roleType, services);

            services.AddScoped(typeof(UserManager<string>));

            var actualBuilder = builder.AddAuthenticator(c=> { });

            AddAuthenticatorTest(builder, actualBuilder, services);
        }

        private void AddAuthenticatorTest(IdentityBuilder builder, IdentityBuilder actualBuilder, ServiceCollection services)
        {
            ServiceCollectionExtensionsTest.AddAuthenticatorTest(services);

            Assert.Equal(builder, actualBuilder);

            Assert.True(services.Where(serviceDescriptor =>
                serviceDescriptor.ServiceType == typeof(AuthenticatorUserManager<string>)
                && serviceDescriptor.Lifetime == ServiceLifetime.Scoped).Count() == 1);
            Assert.True(services.Where(serviceDescriptor =>
                serviceDescriptor.ServiceType == typeof(UserManager<string>)
                && serviceDescriptor.Lifetime == ServiceLifetime.Scoped).Count() == 1);

            Assert.True(services.Where(serviceDescriptor =>
                serviceDescriptor.ServiceType == typeof(AuthenticatorTokenProvider<string>)
                && serviceDescriptor.Lifetime == ServiceLifetime.Transient).Count() == 1);

            Assert.True(services.Where(serviceDescriptor =>
                serviceDescriptor.ServiceType == typeof(IConfigureOptions<IdentityOptions>)
                && serviceDescriptor.Lifetime == ServiceLifetime.Singleton).Count() == 1);

            var IdentityOptions = new IdentityOptions();

            var t = services.Where(serviceDescriptor =>
                 serviceDescriptor.ServiceType == typeof(IConfigureOptions<IdentityOptions>)
                 && serviceDescriptor.Lifetime == ServiceLifetime.Singleton).Select(e => e.ImplementationInstance).First() as IConfigureOptions<IdentityOptions>;

            t.Configure(IdentityOptions);

            Assert.True(IdentityOptions.Tokens.ProviderMap.ContainsKey("Authenticator"));

            Assert.Equal(7, services.Count);
        }
    }
}
