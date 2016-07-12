#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Moq;
using PaulMiami.AspNetCore.Authentication.Authenticator;
using System;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PaulMiami.AspNetCore.Identity.Authenticator.EntityFrameworkCore.Test
{
    public class AuthenticatorUserStoreTest
    {
        [Fact]
        public void SuccessContructor()
        {
            var dbContrext = new Mock<DbContext>(MockBehavior.Strict);
            var authenticatorUserStore = new AuthenticatorUserStore(dbContrext.Object);

            dbContrext.Verify();
        }

        [Fact]
        public void SuccessContructor2()
        {
            var dbContrext = new Mock<DbContext>(MockBehavior.Strict);
            var authenticatorUserStore = new AuthenticatorUserStore<AuthenticatorUser<string>>(dbContrext.Object);

            dbContrext.Verify();
        }

        [Fact]
        public void SuccessContructor3()
        {
            var dbContrext = new Mock<DbContext>(MockBehavior.Strict);
            var authenticatorUserStore = new AuthenticatorUserStore<AuthenticatorUser<string>, IdentityRole<string>, DbContext>(dbContrext.Object);

            dbContrext.Verify();
        }

        [Fact]
        public void SuccessContructor4()
        {
            var dbContrext = new Mock<DbContext>(MockBehavior.Strict);
            var authenticatorUserStore = new AuthenticatorUserStore<AuthenticatorUser<int>, IdentityRole<int>, DbContext, int>(dbContrext.Object);

            dbContrext.Verify();
        }

        [Fact]
        public async Task SqlUserStoreMethodsThrowWhenDisposedTest()
        {
            var store = new AuthenticatorUserStore(new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>().Options));
            store.Dispose();
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.GetAuthenticatorParamsAsync(null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.SetAuthenticatorParamsAsync(null, null));
        }

        [Fact]
        public async Task NullUserGetAuthenticatorParamsAsync()
        {
            var dbContrext = new Mock<DbContext>(MockBehavior.Strict);
            var authenticatorUserStore = new AuthenticatorUserStore(dbContrext.Object);

            await Assert.ThrowsAsync<ArgumentNullException>(()=> authenticatorUserStore.GetAuthenticatorParamsAsync(null));
        }

        [Theory]
        [InlineData(HashAlgorithmType.SHA1, 6, 30)]
        [InlineData(HashAlgorithmType.SHA1, 7, 45)]
        [InlineData(HashAlgorithmType.SHA1, 8, 60)]
        public async Task NullSecretGetAuthenticatorParamsAsync(HashAlgorithmType hashAlgorithm, byte numberOfDigits, byte periodInSeconds)
        {
            var user = new AuthenticatorUser<string>();
            user.AuthenticatorHashAlgorithm = hashAlgorithm;
            user.AuthenticatorNumberOfDigits = numberOfDigits;
            user.AuthenticatorPeriodInSeconds = periodInSeconds;
            var dbContrext = new Mock<DbContext>(MockBehavior.Strict);
            var authenticatorUserStore = new AuthenticatorUserStore(dbContrext.Object);

            var authenticatorParams = await authenticatorUserStore.GetAuthenticatorParamsAsync(user);

            Assert.Equal(user.AuthenticatorHashAlgorithm, authenticatorParams.HashAlgorithm);
            Assert.Equal(user.AuthenticatorNumberOfDigits, authenticatorParams.NumberOfDigits);
            Assert.Equal(user.AuthenticatorPeriodInSeconds, authenticatorParams.PeriodInSeconds);
            Assert.Null(authenticatorParams.Secret);
        }

        [Theory]
        [InlineData(HashAlgorithmType.SHA1, 6, 30)]
        [InlineData(HashAlgorithmType.SHA1, 7, 45)]
        [InlineData(HashAlgorithmType.SHA1, 8, 60)]
        public async Task GetAuthenticatorParamsAsync(HashAlgorithmType hashAlgorithm, byte numberOfDigits, byte periodInSeconds)
        {
            var secret = Guid.NewGuid().ToString();
            var user = new AuthenticatorUser<string>();
            user.AuthenticatorHashAlgorithm = hashAlgorithm;
            user.AuthenticatorNumberOfDigits = numberOfDigits;
            user.AuthenticatorPeriodInSeconds = periodInSeconds;
            user.AuthenticatorSecretEncrypted = Convert.ToBase64String(Encoding.UTF8.GetBytes(secret));
            var dbContrext = new Mock<DbContext>(MockBehavior.Strict);
            var authenticatorUserStore = new AuthenticatorUserStore(dbContrext.Object);

            var authenticatorParams = await authenticatorUserStore.GetAuthenticatorParamsAsync(user);

            Assert.Equal(user.AuthenticatorHashAlgorithm, authenticatorParams.HashAlgorithm);
            Assert.Equal(user.AuthenticatorNumberOfDigits, authenticatorParams.NumberOfDigits);
            Assert.Equal(user.AuthenticatorPeriodInSeconds, authenticatorParams.PeriodInSeconds);
            Assert.Equal(Encoding.UTF8.GetBytes(secret), authenticatorParams.Secret);
        }

        [Fact]
        public async Task NullUserSetAuthenticatorParamsAsync()
        {
            var dbContrext = new Mock<DbContext>(MockBehavior.Strict);
            var authenticatorUserStore = new AuthenticatorUserStore(dbContrext.Object);

            await Assert.ThrowsAsync<ArgumentNullException>(() => authenticatorUserStore.SetAuthenticatorParamsAsync(null, new AuthenticatorParams()));
        }

        [Fact]
        public async Task NullAuthenticatorParamsrSetAuthenticatorParamsAsync()
        {
            var user = new AuthenticatorUser<string>();
            var dbContrext = new Mock<DbContext>(MockBehavior.Strict);
            var authenticatorUserStore = new AuthenticatorUserStore(dbContrext.Object);

            await Assert.ThrowsAsync<ArgumentNullException>(() => authenticatorUserStore.SetAuthenticatorParamsAsync(user, null));
        }


        [Theory]
        [InlineData(HashAlgorithmType.SHA1, 6, 30)]
        [InlineData(HashAlgorithmType.SHA1, 7, 45)]
        [InlineData(HashAlgorithmType.SHA1, 8, 60)]
        public async Task NullSecretSetAuthenticatorParamsAsync(HashAlgorithmType hashAlgorithm, byte numberOfDigits, byte periodInSeconds)
        {
            var user = new AuthenticatorUser<string>();
            var authenticatorParams = new AuthenticatorParams();
            authenticatorParams.HashAlgorithm = hashAlgorithm;
            authenticatorParams.NumberOfDigits = numberOfDigits;
            authenticatorParams.PeriodInSeconds = periodInSeconds;
            var dbContrext = new Mock<DbContext>(MockBehavior.Strict);
            var authenticatorUserStore = new AuthenticatorUserStore(dbContrext.Object);

            await authenticatorUserStore.SetAuthenticatorParamsAsync(user, authenticatorParams);

            Assert.Equal(authenticatorParams.HashAlgorithm, user.AuthenticatorHashAlgorithm);
            Assert.Equal(authenticatorParams.NumberOfDigits, user.AuthenticatorNumberOfDigits);
            Assert.Equal(authenticatorParams.PeriodInSeconds, user.AuthenticatorPeriodInSeconds);
            Assert.Null(user.AuthenticatorSecretEncrypted);
        }

        [Theory]
        [InlineData(HashAlgorithmType.SHA1, 6, 30)]
        [InlineData(HashAlgorithmType.SHA1, 7, 45)]
        [InlineData(HashAlgorithmType.SHA1, 8, 60)]
        public async Task SetAuthenticatorParamsAsync(HashAlgorithmType hashAlgorithm, byte numberOfDigits, byte periodInSeconds)
        {
            var secret = Guid.NewGuid().ToString();
            var user = new AuthenticatorUser<string>();
            var authenticatorParams = new AuthenticatorParams();
            authenticatorParams.HashAlgorithm = hashAlgorithm;
            authenticatorParams.NumberOfDigits = numberOfDigits;
            authenticatorParams.PeriodInSeconds = periodInSeconds;
            authenticatorParams.Secret = Encoding.UTF8.GetBytes(secret);
            var dbContrext = new Mock<DbContext>(MockBehavior.Strict);
            var authenticatorUserStore = new AuthenticatorUserStore(dbContrext.Object);

            await authenticatorUserStore.SetAuthenticatorParamsAsync(user, authenticatorParams);

            Assert.Equal(authenticatorParams.HashAlgorithm, user.AuthenticatorHashAlgorithm);
            Assert.Equal(authenticatorParams.NumberOfDigits, user.AuthenticatorNumberOfDigits);
            Assert.Equal(authenticatorParams.PeriodInSeconds, user.AuthenticatorPeriodInSeconds);
            Assert.Equal(Convert.ToBase64String(authenticatorParams.Secret), user.AuthenticatorSecretEncrypted);
        }
    }
}
