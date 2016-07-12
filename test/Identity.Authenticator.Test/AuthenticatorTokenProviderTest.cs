#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Moq;
using PaulMiami.AspNetCore.Authentication.Authenticator;
using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace PaulMiami.AspNetCore.Identity.Authenticator.Test
{
    public class AuthenticatorTokenProviderTest
    {
        [Fact]
        public void SuccessConstructor()
        {
            var authenticationService = new Mock<IAuthenticatorService>(MockBehavior.Strict);

            var authenticatorTokenProvider = new AuthenticatorTokenProvider<string>(authenticationService.Object);

            authenticationService.Verify();
        }

        [Fact]
        public void NullAuthenticatorServiceConstructor()
        {
            Assert.Throws<ArgumentNullException>(() => new AuthenticatorTokenProvider<string>(null));
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task SuccessCanGenerateTwoFactorTokenAsync(bool expected)
        {
            var user = Guid.NewGuid().ToString();
            var authenticationService = new Mock<IAuthenticatorService>(MockBehavior.Strict);

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = AuthenticatorUserManagerTest.GetAuthenticatorUserManagerMock<string>(out userStore, out dataProtector, out authenticatorService);

            authenticatorUserManager
                .Setup(a => a.GetAuthenticatorEnabledAsync(user, default(CancellationToken)))
                .Returns(Task.FromResult(expected))
                .Verifiable();

            var authenticatorTokenProvider = new AuthenticatorTokenProvider<string>(authenticationService.Object);

            var result = await authenticatorTokenProvider.CanGenerateTwoFactorTokenAsync(authenticatorUserManager.Object, user);
            Assert.Equal(expected, result);

            authenticationService.Verify();
            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task InvalidOperationGenerateAsync()
        {
            var user = Guid.NewGuid().ToString();
            var authenticationService = new Mock<IAuthenticatorService>(MockBehavior.Strict);

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = AuthenticatorUserManagerTest.GetAuthenticatorUserManagerMock<string>(out userStore, out dataProtector, out authenticatorService);

            var authenticatorTokenProvider = new AuthenticatorTokenProvider<string>(authenticationService.Object);

            await Assert.ThrowsAsync<InvalidOperationException>(()=>authenticatorTokenProvider.GenerateAsync(Guid.NewGuid().ToString(), authenticatorUserManager.Object, user));

            authenticationService.Verify();
            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task SuccessValidateAsync(bool valid)
        {
            var rand = new Random(DateTime.Now.Millisecond);
            var user = Guid.NewGuid().ToString();
            var code = rand.Next(999999);
            string token = null;
            if(valid)
                token = code.ToString();
            else
                token = rand.Next(999999).ToString();

            var authenticationService = new Mock<IAuthenticatorService>(MockBehavior.Strict);
            var authenticatorParams = new AuthenticatorParams();

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = AuthenticatorUserManagerTest.GetAuthenticatorUserManagerMock<string>(out userStore, out dataProtector, out authenticatorService);

            authenticatorUserManager
                .Setup(a => a.GetAuthenticatorParamsAsync(user, default(CancellationToken)))
                .Returns(Task.FromResult(authenticatorParams))
                .Verifiable();

            authenticationService
                .Setup(a => a.GetCode(
                    authenticatorParams.HashAlgorithm,
                    authenticatorParams.Secret,
                    authenticatorParams.NumberOfDigits,
                    authenticatorParams.PeriodInSeconds))
                .Returns(code)
                .Verifiable();

            var authenticatorTokenProvider = new AuthenticatorTokenProvider<string>(authenticationService.Object);

            var result = await authenticatorTokenProvider.ValidateAsync(Guid.NewGuid().ToString(), token, authenticatorUserManager.Object, user);

            Assert.Equal(valid, result);

            authenticationService.Verify();
            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task InvalidTokenValidateAsync()
        {
            var rand = new Random(DateTime.Now.Millisecond);
            var user = Guid.NewGuid().ToString();
            var code = rand.Next(999999);
            string token = "bad";

            var authenticationService = new Mock<IAuthenticatorService>(MockBehavior.Strict);
            var authenticatorParams = new AuthenticatorParams();

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = AuthenticatorUserManagerTest.GetAuthenticatorUserManagerMock<string>(out userStore, out dataProtector, out authenticatorService);

            var authenticatorTokenProvider = new AuthenticatorTokenProvider<string>(authenticationService.Object);

            var result = await authenticatorTokenProvider.ValidateAsync(Guid.NewGuid().ToString(), token, authenticatorUserManager.Object, user);

            Assert.False(result);

            authenticationService.Verify();
            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task UserAuthenticatorStoreNotImplemented()
        {
            var rand = new Random(DateTime.Now.Millisecond);
            var user = Guid.NewGuid().ToString();
            var code = rand.Next(999999).ToString();

            var authenticationService = new Mock<IAuthenticatorService>(MockBehavior.Strict);


            var userStore = new Mock<IUserAuthenticatorStore<string>>(MockBehavior.Strict);

            var userManager = new UserManager<string>(userStore.Object,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null);

            var authenticatorTokenProvider = new AuthenticatorTokenProvider<string>(authenticationService.Object);

            Action<Exception> validateMessage = (x) => Assert.Equal("UserManager should inherit from AuthenticatorUserManager<TUser>.", x.Message);

            var ex = await Assert.ThrowsAsync<NotSupportedException>(() => authenticatorTokenProvider.CanGenerateTwoFactorTokenAsync(userManager, user));
            validateMessage(ex);
            ex = await Assert.ThrowsAsync<NotSupportedException>(() => authenticatorTokenProvider.ValidateAsync(string.Empty, code, userManager, user));
            validateMessage(ex);

            authenticationService.Verify();
            userStore.Verify();
        }

    }
}
