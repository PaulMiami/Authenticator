#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;

namespace PaulMiami.AspNetCore.Authentication.Authenticator
{
    public static class ServiceCollectionExtensions
    {
        public static void AddAuthenticator(this IServiceCollection services, AuthenticatorServiceOptions configureOptions)
        {
            configureOptions.CheckArgumentNull(nameof(configureOptions));

            services.TryAddSingleton(Options.Create(configureOptions));
            services.TryAddSingleton<ISystemTime, DefaultSystemTime>();
            services.TryAddSingleton<IAuthenticatorService, AuthenticatorService>();
        }

        public static void AddAuthenticator(this IServiceCollection services, Action<AuthenticatorServiceOptions> configuration)
        {
            configuration.CheckArgumentNull(nameof(configuration));

            var configureOptions = new AuthenticatorServiceOptions();

            configuration(configureOptions);

            AddAuthenticator(services, configureOptions);
        }
    }
}
