#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using System;
using Xunit;

namespace PaulMiami.AspNetCore.Identity.Authenticator.EntityFrameworkCore.Test
{
    public class AuthenticatorUserTest
    {
        [Fact]
        public void SuccessContructor()
        {
            var authenticatorUser = new AuthenticatorUser();
            Assert.NotEqual(string.Empty, authenticatorUser.Id);
        }

        [Fact]
        public void SuccessUsernameContructor()
        {
            var userName = Guid.NewGuid().ToString();
            var authenticatorUser = new AuthenticatorUser(userName);
            Assert.NotEqual(string.Empty, authenticatorUser.Id);
            Assert.Equal(userName, authenticatorUser.UserName);
        }
    }
}
