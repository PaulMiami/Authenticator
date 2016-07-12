#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Moq;
using PaulMiami.AspNetCore.Authentication.Authenticator;
using System;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PaulMiami.AspNetCore.Identity.Authenticator.Test
{
    public class AuthenticatorUserManagerTest
    {
        internal static AuthenticatorUserManager<TUser> GetAuthenticatorUserManager<TUser>(
            out Mock<IUserAuthenticatorStore<TUser>> userStore,
            out Mock<IDataProtectionProvider> dataProtectionProvider, 
            out Mock<IAuthenticatorService> authenticatorService,
            MockBehavior mockBehavior = MockBehavior.Default,
            Action<Mock<IUserAuthenticatorStore<TUser>>, Mock<IDataProtectionProvider>, Mock<IAuthenticatorService>> setup = null) where TUser: class
        {
            userStore = new Mock<IUserAuthenticatorStore<TUser>>(mockBehavior);
            dataProtectionProvider = new Mock<IDataProtectionProvider>(mockBehavior);
            authenticatorService = new Mock<IAuthenticatorService>(mockBehavior);

            setup?.Invoke(userStore, dataProtectionProvider, authenticatorService);

            var authenticatorUserManager = new AuthenticatorUserManager<TUser>(
                userStore.Object,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                dataProtectionProvider.Object,
                authenticatorService.Object
                );

            return authenticatorUserManager;
        }

        internal static AuthenticatorUserManager<TUser> GetAuthenticatorUserManager<TUser>(
            out Mock<IUserAuthenticatorStore<TUser>> userStore,
            out Mock<IDataProtector> dataProtector,
            out Mock<IAuthenticatorService> authenticatorService,
            MockBehavior mockBehavior = MockBehavior.Default) where TUser : class
        {
            userStore = new Mock<IUserAuthenticatorStore<TUser>>(mockBehavior);
            var dataProtectionProvider = new Mock<IDataProtectionProvider>(mockBehavior);
            dataProtector = new Mock<IDataProtector>(mockBehavior);
            authenticatorService = new Mock<IAuthenticatorService>(mockBehavior);

            dataProtectionProvider
                .Setup(s => s.CreateProtector("AuthenticatorUserManager"))
                .Returns(dataProtector.Object)
                .Verifiable();

            var authenticatorUserManager = new AuthenticatorUserManager<TUser>(
                userStore.Object,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                dataProtectionProvider.Object,
                authenticatorService.Object
                );

            return authenticatorUserManager;
        }

        internal static Mock<AuthenticatorUserManager<TUser>> GetAuthenticatorUserManagerMock<TUser>(
            out Mock<IUserAuthenticatorStore<TUser>> userStore,
            out Mock<IDataProtector> dataProtector,
            out Mock<IAuthenticatorService> authenticatorService,
            MockBehavior mockBehavior = MockBehavior.Default) where TUser : class
        {
            userStore = new Mock<IUserAuthenticatorStore<TUser>>(mockBehavior);
            var dataProtectionProvider = new Mock<IDataProtectionProvider>(mockBehavior);
            dataProtector = new Mock<IDataProtector>(mockBehavior);
            authenticatorService = new Mock<IAuthenticatorService>(mockBehavior);

            dataProtectionProvider
                .Setup(s => s.CreateProtector("AuthenticatorUserManager"))
                .Returns(dataProtector.Object)
                .Verifiable();

            var authenticatorUserManager = new Mock<AuthenticatorUserManager<TUser>>(
                MockBehavior.Default,
                userStore.Object,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                dataProtectionProvider.Object,
                authenticatorService.Object
                );

            return authenticatorUserManager;
        }

        [Fact]
        public void SuccessConstructor()
        {
            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtectionProvider> dataProtectionProvider;
            Mock<IAuthenticatorService> authenticatorService;
            var dataProtector = new Mock<IDataProtector>(MockBehavior.Strict);

            var authenticatorUserManager = GetAuthenticatorUserManager(
                out userStore, 
                out dataProtectionProvider, 
                out authenticatorService,
                MockBehavior.Strict,
                (u, d, a)=>
                {
                    d
                    .Setup(s => s.CreateProtector("AuthenticatorUserManager"))
                    .Returns(dataProtector.Object)
                    .Verifiable();
                });

            dataProtector.Verify();
            dataProtectionProvider.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public void NullAuthenticatorServiceConstructor()
        {
            var userStore = new Mock<IUserStore<string>>(MockBehavior.Strict);
            var dataProtectionProvider = new Mock<IDataProtectionProvider>(MockBehavior.Strict);

            Assert.Throws<ArgumentNullException>(() =>
                new AuthenticatorUserManager<string>(
                userStore.Object,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                dataProtectionProvider.Object,
                null
                ));

            userStore.Verify();
            dataProtectionProvider.Verify();
        }

        [Fact]
        public void NullDataProtectionProviderConstructor()
        {
            var userStore = new Mock<IUserStore<string>>(MockBehavior.Strict);
            var authenticatorService = new Mock<IAuthenticatorService>(MockBehavior.Strict);

            Assert.Throws<ArgumentNullException>(() =>
                new AuthenticatorUserManager<string>(
                userStore.Object,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                authenticatorService.Object
                ));

            userStore.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task MethodsThrowWhenDisposedTest()
        {
            var userStore = new Mock<IUserStore<string>>();
            var dataProtectionProvider = new Mock<IDataProtectionProvider>();
            var authenticatorService = new Mock<IAuthenticatorService>();
            var dataProtector = new Mock<IDataProtector>();

            dataProtectionProvider
                .Setup(s => s.CreateProtector("AuthenticatorUserManager"))
                .Returns(dataProtector.Object)
                .Verifiable();

            var authenticatorUserManager = new AuthenticatorUserManager<string>(
                userStore.Object,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                dataProtectionProvider.Object,
                authenticatorService.Object
                );

            Action<Exception> validateMessage = (x) => Assert.Equal("Store does not implement IUserAuthenticatorStore<TUser>.", x.Message);

            var ex = await Assert.ThrowsAsync<NotSupportedException>(() => authenticatorUserManager.GetAuthenticatorEnabledAsync(null));
            validateMessage(ex);
            ex = await Assert.ThrowsAsync<NotSupportedException>(() => authenticatorUserManager.GetAuthenticatorParamsAsync(null));
            validateMessage(ex);
            ex = await Assert.ThrowsAsync<NotSupportedException>(() => authenticatorUserManager.EnableAuthenticatorAsync(null, new Authenticator(), string.Empty));
            validateMessage(ex);
            ex = await Assert.ThrowsAsync<NotSupportedException>(() => authenticatorUserManager.DisableAuthenticatorAsync(null, string.Empty));
            validateMessage(ex);
            ex = await Assert.ThrowsAsync<NotSupportedException>(() => authenticatorUserManager.CreateAuthenticatorAsync(null));
            validateMessage(ex);
        }

        [Fact]
        public async Task UserAuthenticatorStoreNotImplemented()
        {
            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtectionProvider> dataProtectionProvider;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = GetAuthenticatorUserManager(out userStore, out dataProtectionProvider, out authenticatorService);

            authenticatorUserManager.Dispose();
            await Assert.ThrowsAsync<ObjectDisposedException>(() => authenticatorUserManager.GetAuthenticatorEnabledAsync(null));
            await Assert.ThrowsAsync<ObjectDisposedException>(() => authenticatorUserManager.GetAuthenticatorParamsAsync(null));
            await Assert.ThrowsAsync<ObjectDisposedException>(() => authenticatorUserManager.EnableAuthenticatorAsync(null, null, null));
            await Assert.ThrowsAsync<ObjectDisposedException>(() => authenticatorUserManager.DisableAuthenticatorAsync(null, null));
            await Assert.ThrowsAsync<ObjectDisposedException>(() => authenticatorUserManager.CreateAuthenticatorAsync(null));
        }

        [Fact]
        public async Task SuccessEnableGetAuthenticatorEnabledAsync()
        {
            var user = Guid.NewGuid().ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var authenticatorParams = new AuthenticatorParams
            {
                Secret = new byte[0]
            };

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = GetAuthenticatorUserManager(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);

            userStore.Setup(a => a.GetAuthenticatorParamsAsync(user, cancellationToken))
                .Returns(Task.FromResult(authenticatorParams))
                .Verifiable();

            Assert.True(await authenticatorUserManager.GetAuthenticatorEnabledAsync(user, cancellationToken));

            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task SuccessDisableGetAuthenticatorEnabledAsync()
        {
            var user = Guid.NewGuid().ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var authenticatorParams = new AuthenticatorParams
            {
                Secret = null
            };

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = GetAuthenticatorUserManager(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);

            userStore.Setup(a => a.GetAuthenticatorParamsAsync(user, cancellationToken))
                .Returns(Task.FromResult(authenticatorParams))
                .Verifiable();

            Assert.False(await authenticatorUserManager.GetAuthenticatorEnabledAsync(user, cancellationToken));

            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task NullUserGetAuthenticatorEnabledAsync()
        {
            var cancellationToken = new System.Threading.CancellationToken();

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = GetAuthenticatorUserManager(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);

            await Assert.ThrowsAnyAsync<ArgumentNullException>(()=> authenticatorUserManager.GetAuthenticatorEnabledAsync(null, cancellationToken));

            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task SuccessGetAuthenticatorParamsAsync()
        {
            var user = Guid.NewGuid().ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var authenticatorParamsActual = new AuthenticatorParams
            {
                Secret = Encoding.UTF8.GetBytes("ENCRYPTED")
            };

            var unprotectedData = Encoding.UTF8.GetBytes("CLEARTEXT");

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = GetAuthenticatorUserManager(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);

            userStore.Setup(a => a.GetAuthenticatorParamsAsync(user, cancellationToken))
                .Returns(Task.FromResult(authenticatorParamsActual))
                .Verifiable();

            dataProtector.Setup(a => a.Unprotect(authenticatorParamsActual.Secret))
                .Returns(unprotectedData)
                .Verifiable();

            var authenticatorParams = await authenticatorUserManager.GetAuthenticatorParamsAsync(user, cancellationToken);

            Assert.Equal(authenticatorParams, authenticatorParamsActual);
            Assert.Equal(unprotectedData, authenticatorParamsActual.Secret);

            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task NullUserGetAuthenticatorParamsAsync()
        {
            var user = Guid.NewGuid().ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var authenticatorParamsActual = new AuthenticatorParams
            {
                Secret = Encoding.UTF8.GetBytes("ENCRYPTED")
            };

            var unprotectedData = Encoding.UTF8.GetBytes("CLEARTEXT");

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = GetAuthenticatorUserManager(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);

            await Assert.ThrowsAsync<ArgumentNullException>(()=> authenticatorUserManager.GetAuthenticatorParamsAsync(null, cancellationToken));

            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Theory]
        [InlineData(HashAlgorithmType.SHA1, 30, 6)]
        [InlineData(HashAlgorithmType.SHA256, 45, 7)]
        [InlineData(HashAlgorithmType.SHA512, 60, 8)]
        public async Task SuccessEnableAuthenticatorAsync(HashAlgorithmType HashAlgorithm, byte periodInSeconds, byte numberOfDigits)
        {
            var ran = new Random(DateTime.Today.Millisecond);
            var user = Guid.NewGuid().ToString();
            var code = ran.Next(999999);
            var codeInput = code.ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var authenticator = new Authenticator
            {
                Secret = Encoding.UTF8.GetBytes("CLEARTEXT"),
                HashAlgorithm = HashAlgorithm,
                PeriodInSeconds = periodInSeconds,
                NumberOfDigits = numberOfDigits
            };
            var authenticatorParams = new AuthenticatorParams();
            var protectedData = Encoding.UTF8.GetBytes("ENCRYPTED");

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManagerMock = GetAuthenticatorUserManagerMock(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);
            authenticatorUserManagerMock.CallBase = true;
            var authenticatorUserManager = authenticatorUserManagerMock.Object;

            authenticatorUserManagerMock
                .Setup(a => a.GetAuthenticatorEnabledAsync(user, cancellationToken))
                .Returns(Task.FromResult(false))
                .Verifiable();

            authenticatorService
                .Setup(a => a.GetCode(authenticator.HashAlgorithm, authenticator.Secret, authenticator.NumberOfDigits, authenticator.PeriodInSeconds))
                .Returns(code)
                .Verifiable();

            dataProtector
                .Setup(a => a.Protect(authenticator.Secret))
                .Returns(protectedData)
                .Verifiable();

            userStore
                .Setup(a => a.SetAuthenticatorParamsAsync(user, It.Is<AuthenticatorParams>((auth) =>
                    auth.HashAlgorithm == authenticator.HashAlgorithm &&
                    auth.NumberOfDigits == authenticator.NumberOfDigits &&
                    auth.PeriodInSeconds == authenticator.PeriodInSeconds &&
                    auth.Secret == protectedData
                ), cancellationToken))
                .Returns(Task.FromResult(0))
                .Verifiable();

            authenticatorUserManagerMock
                .Setup(a => a.UpdateAsync(user))
                .Returns(Task.FromResult(new IdentityResult()))
                .Verifiable();

            var result = await authenticatorUserManager.EnableAuthenticatorAsync(user, authenticator, codeInput, cancellationToken);

            Assert.True(result);

            authenticatorUserManagerMock.Verify();
            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task FailWrongCodeEnableAuthenticatorAsync()
        {
            var ran = new Random(DateTime.Today.Millisecond);
            var user = Guid.NewGuid().ToString();
            var code = ran.Next(999999);
            var codeInput = ran.Next(999999).ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var authenticator = new Authenticator();
            var authenticatorParams = new AuthenticatorParams();
            var protectedData = Encoding.UTF8.GetBytes("ENCRYPTED");

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManagerMock = GetAuthenticatorUserManagerMock(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);
            authenticatorUserManagerMock.CallBase = true;
            var authenticatorUserManager = authenticatorUserManagerMock.Object;

            authenticatorUserManagerMock
                .Setup(a => a.GetAuthenticatorEnabledAsync(user, cancellationToken))
                .Returns(Task.FromResult(false))
                .Verifiable();

            authenticatorService
                .Setup(a => a.GetCode(authenticator.HashAlgorithm, authenticator.Secret, authenticator.NumberOfDigits, authenticator.PeriodInSeconds))
                .Returns(code)
                .Verifiable();

            var result = await authenticatorUserManager.EnableAuthenticatorAsync(user, authenticator, codeInput, cancellationToken);

            Assert.False(result);

            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
            authenticatorUserManagerMock.Verify();
        }

        [Fact]
        public async Task FailAuthenticatorEnableCodeEnableAuthenticatorAsync()
        {
            var ran = new Random(DateTime.Today.Millisecond);
            var user = Guid.NewGuid().ToString();
            var codeInput = ran.Next(999999).ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var authenticator = new Authenticator();

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManagerMock = GetAuthenticatorUserManagerMock(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);
            authenticatorUserManagerMock.CallBase = true;
            var authenticatorUserManager = authenticatorUserManagerMock.Object;

            authenticatorUserManagerMock
                .Setup(a => a.GetAuthenticatorEnabledAsync(user, cancellationToken))
                .Returns(Task.FromResult(true))
                .Verifiable();

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(()=>authenticatorUserManager.EnableAuthenticatorAsync(user, authenticator, codeInput, cancellationToken));
            Assert.Equal("This user already has an authenticator enabled.", ex.Message);

            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
            authenticatorUserManagerMock.Verify();
        }

        [Fact]
        public async Task NullUserEnableAuthenticatorAsync()
        {
            var ran = new Random(DateTime.Today.Millisecond);
            var codeInput = ran.Next(999999).ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var authenticator = new Authenticator();

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = GetAuthenticatorUserManager(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);

             await Assert.ThrowsAsync<ArgumentNullException>(()=>authenticatorUserManager.EnableAuthenticatorAsync(null, authenticator, codeInput, cancellationToken));

            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task NullAuthenticatorEnableAuthenticatorAsync()
        {
            var ran = new Random(DateTime.Today.Millisecond);
            var user = Guid.NewGuid().ToString();
            var codeInput = ran.Next(999999).ToString();
            var cancellationToken = new System.Threading.CancellationToken();

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = GetAuthenticatorUserManager(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);

            await Assert.ThrowsAsync<ArgumentNullException>(() => authenticatorUserManager.EnableAuthenticatorAsync(user, null, codeInput, cancellationToken));

            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task SuccessDisableAuthenticatorAsync()
        {
            var ran = new Random(DateTime.Today.Millisecond);
            var user = Guid.NewGuid().ToString();
            var code = ran.Next(999999);
            var codeInput = code.ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var unprotectedData = Encoding.UTF8.GetBytes("CLEARTEXT");
            var authenticatorParams = new AuthenticatorParams
            {
                Secret = unprotectedData
            };

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManagerMock = GetAuthenticatorUserManagerMock(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);
            authenticatorUserManagerMock.CallBase = true;
            var authenticatorUserManager = authenticatorUserManagerMock.Object;

            authenticatorUserManagerMock
                .Setup(a=>a.GetAuthenticatorParamsAsync(user, cancellationToken))
                .Returns(Task.FromResult(authenticatorParams))
                .Verifiable();

            authenticatorService
                .Setup(a => a.GetCode(authenticatorParams.HashAlgorithm, unprotectedData, authenticatorParams.NumberOfDigits, authenticatorParams.PeriodInSeconds))
                .Returns(code)
                .Verifiable();

            userStore
                .Setup(a => a.SetAuthenticatorParamsAsync(user, It.Is<AuthenticatorParams>((auth) =>
                    auth.HashAlgorithm == HashAlgorithmType.SHA1 &&
                    auth.NumberOfDigits == 0 &&
                    auth.PeriodInSeconds == 0 &&
                    auth.Secret == null
                ), cancellationToken))
                .Returns(Task.FromResult(0))
                .Verifiable();

            authenticatorUserManagerMock
                .Setup(a => a.UpdateAsync(user))
                .Returns(Task.FromResult(new IdentityResult()))
                .Verifiable();

            var result = await authenticatorUserManager.DisableAuthenticatorAsync(user, codeInput, cancellationToken);

            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
            authenticatorUserManagerMock.Verify();

            Assert.True(result);
        }

        [Fact]
        public async Task FailDisableAuthenticatorAsync()
        {
            var ran = new Random(DateTime.Today.Millisecond);
            var user = Guid.NewGuid().ToString();
            var code = ran.Next(999999);
            var codeInput = ran.Next(999999).ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var unprotectedData = Encoding.UTF8.GetBytes("CLEARTEXT");
            var authenticatorParams = new AuthenticatorParams
            {
                Secret = unprotectedData
            };

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManagerMock = GetAuthenticatorUserManagerMock(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);
            authenticatorUserManagerMock.CallBase = true;
            var authenticatorUserManager = authenticatorUserManagerMock.Object;

            authenticatorUserManagerMock
                .Setup(a => a.GetAuthenticatorParamsAsync(user, cancellationToken))
                .Returns(Task.FromResult(authenticatorParams))
                .Verifiable();

            authenticatorService
                .Setup(a => a.GetCode(authenticatorParams.HashAlgorithm, unprotectedData, authenticatorParams.NumberOfDigits, authenticatorParams.PeriodInSeconds))
                .Returns(code)
                .Verifiable();
            
            var result = await authenticatorUserManager.DisableAuthenticatorAsync(user, codeInput, cancellationToken);

            Assert.False(result);

            authenticatorUserManagerMock.Verify();
            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task NullUserDisableAuthenticatorAsync()
        {
            var ran = new Random(DateTime.Today.Millisecond);
            var codeInput = ran.Next(999999).ToString();
            var cancellationToken = new System.Threading.CancellationToken();

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = GetAuthenticatorUserManager(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);

            await Assert.ThrowsAsync<ArgumentNullException>(()=>authenticatorUserManager.DisableAuthenticatorAsync(null, codeInput, cancellationToken));

            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task BadCodeDisableAuthenticatorAsync()
        {
            var ran = new Random(DateTime.Today.Millisecond);
            var codeInput = "Bad";
            var user = Guid.NewGuid().ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var authenticatorParams = new AuthenticatorParams();
            var unprotectedData = Encoding.UTF8.GetBytes("CLEARTEXT");

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManager = GetAuthenticatorUserManager(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);

            userStore
                .Setup(a => a.GetAuthenticatorParamsAsync(user, cancellationToken))
                .Returns(Task.FromResult(authenticatorParams))
                .Verifiable();

            dataProtector
                .Setup(a => a.Unprotect(authenticatorParams.Secret))
                .Returns(unprotectedData)
                .Verifiable();

            Assert.False(await authenticatorUserManager.DisableAuthenticatorAsync(user, codeInput, cancellationToken));

            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Theory]
        [InlineData(HashAlgorithmType.SHA1, 30, 6, 20)]
        [InlineData(HashAlgorithmType.SHA256, 45, 7, 32)]
        [InlineData(HashAlgorithmType.SHA512, 60, 8, 64)]
        public async Task SuccessCreateAuthenticatorAsync(HashAlgorithmType hashAlgorithm, byte periodInSeconds, byte numberOfDigits, int secretLength)
        {
            var user = Guid.NewGuid().ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var email = Guid.NewGuid().ToString();
            var uri = Guid.NewGuid().ToString();

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManagerMock = GetAuthenticatorUserManagerMock(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);
            authenticatorUserManagerMock.CallBase = true;
            var authenticatorUserManager = authenticatorUserManagerMock.Object;

            authenticatorUserManagerMock
                .Setup(a => a.GetAuthenticatorEnabledAsync(user, cancellationToken))
                .Returns(Task.FromResult(false))
                .Verifiable();

            authenticatorUserManagerMock
                .Setup(a => a.GetEmailAsync(user))
                .Returns(Task.FromResult(email))
                .Verifiable();

            authenticatorService
                .Setup(a => a.HashAlgorithm)
                .Returns(hashAlgorithm)
                .Verifiable();

            authenticatorService
                .Setup(a => a.NumberOfDigits)
                .Returns(numberOfDigits)
                .Verifiable();

            authenticatorService
                .Setup(a => a.PeriodInSeconds)
                .Returns(periodInSeconds)
                .Verifiable();

            authenticatorService
                .Setup(a => a.GetUri(email, It.Is<byte[]>(b=>b.Length == secretLength)))
                .Returns(uri)
                .Verifiable();

            var result = await authenticatorUserManager.CreateAuthenticatorAsync(user, cancellationToken);

            authenticatorUserManagerMock.Verify();
            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();

            Assert.Equal(hashAlgorithm, result.HashAlgorithm);
            Assert.Equal(numberOfDigits, result.NumberOfDigits);
            Assert.Equal(periodInSeconds, result.PeriodInSeconds);
            Assert.Equal(uri, result.Uri);
            Assert.Equal(secretLength, result.Secret.Length);
        }

        [Fact]
        public async Task InvalidHasAlgorithmCreateAuthenticatorAsync()
        {
            var user = Guid.NewGuid().ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var email = Guid.NewGuid().ToString();

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManagerMock = GetAuthenticatorUserManagerMock(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);
            authenticatorUserManagerMock.CallBase = true;
            var authenticatorUserManager = authenticatorUserManagerMock.Object;

            authenticatorUserManagerMock
                .Setup(a => a.GetAuthenticatorEnabledAsync(user, cancellationToken))
                .Returns(Task.FromResult(false))
                .Verifiable();

            authenticatorUserManagerMock
                .Setup(a => a.GetEmailAsync(user))
                .Returns(Task.FromResult(email))
                .Verifiable();

            authenticatorService
                .Setup(a => a.HashAlgorithm)
                .Returns((HashAlgorithmType)100)
                .Verifiable();

            await Assert.ThrowsAsync<ArgumentException>(() => authenticatorUserManager.CreateAuthenticatorAsync(user, cancellationToken));

            authenticatorUserManagerMock.Verify();
            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }

        [Fact]
        public async Task FailAuthenticatorEnableCreateAuthenticatorAsync()
        {
            var user = Guid.NewGuid().ToString();
            var cancellationToken = new System.Threading.CancellationToken();
            var email = Guid.NewGuid().ToString();

            Mock<IUserAuthenticatorStore<string>> userStore;
            Mock<IDataProtector> dataProtector;
            Mock<IAuthenticatorService> authenticatorService;

            var authenticatorUserManagerMock = GetAuthenticatorUserManagerMock(out userStore, out dataProtector, out authenticatorService, MockBehavior.Strict);
            authenticatorUserManagerMock.CallBase = true;
            var authenticatorUserManager = authenticatorUserManagerMock.Object;

            authenticatorUserManagerMock
                .Setup(a => a.GetAuthenticatorEnabledAsync(user, cancellationToken))
                .Returns(Task.FromResult(true))
                .Verifiable();

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(()=>authenticatorUserManager.CreateAuthenticatorAsync(user, cancellationToken));
            Assert.Equal("This user already has an authenticator enabled.", ex.Message);

            authenticatorUserManagerMock.Verify();
            userStore.Verify();
            dataProtector.Verify();
            authenticatorService.Verify();
        }
    }
}
