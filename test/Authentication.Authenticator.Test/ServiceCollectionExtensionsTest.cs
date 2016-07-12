#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using Xunit;

namespace PaulMiami.AspNetCore.Authentication.Authenticator.Test
{
    public class ServiceCollectionExtensionsTest
    {
        [Fact]
        public void NullOptions()
        {
            var services = new ServiceCollection();

            Assert.Throws<ArgumentNullException>(()=>services.AddAuthenticator((AuthenticatorServiceOptions)null));
        }

        [Fact]
        public void NullAction()
        {
            var services = new ServiceCollection();

            Assert.Throws<ArgumentNullException>(() => services.AddAuthenticator((Action<AuthenticatorServiceOptions>)null));
        }

        [Fact]
        public void Success()
        {
            var services = new ServiceCollection();

            services.AddAuthenticator(new AuthenticatorServiceOptions());

            AddAuthenticatorTest(services);
            Assert.Equal(3, services.Count);
        }

        [Fact]
        public void SuccessAction()
        {
            var services = new ServiceCollection();

            services.AddAuthenticator(c=> { });

            AddAuthenticatorTest(services);
            Assert.Equal(3, services.Count);
        }

        public static void AddAuthenticatorTest(ServiceCollection services)
        {
            Assert.True(services.Where(serviceDescriptor => serviceDescriptor.ServiceType == typeof(IOptions<AuthenticatorServiceOptions>)).Count() == 1);
            Assert.True(services.Where(serviceDescriptor => serviceDescriptor.ServiceType == typeof(ISystemTime)).Count() == 1);
            Assert.True(services.Where(serviceDescriptor => serviceDescriptor.ServiceType == typeof(IAuthenticatorService)).Count() == 1);
        }
    }
}
