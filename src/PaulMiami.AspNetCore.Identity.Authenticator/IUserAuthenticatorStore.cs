#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using System.Threading;

namespace PaulMiami.AspNetCore.Identity.Authenticator
{
    public interface IUserAuthenticatorStore<TUser> : IUserStore<TUser> where TUser : class
    {
        Task<AuthenticatorParams> GetAuthenticatorParamsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken));

        Task SetAuthenticatorParamsAsync(TUser user, AuthenticatorParams authenticatorParams, CancellationToken cancellationToken = default(CancellationToken));
    }
}
