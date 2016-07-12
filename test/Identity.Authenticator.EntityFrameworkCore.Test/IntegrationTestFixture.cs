#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using PaulMiami.AspNetCore.Authentication.Authenticator;
using System;
using System.IO;
using System.Net.Http;
using System.Text;
using TestSite.Data;

namespace PaulMiami.AspNetCore.Identity.Authenticator.EntityFrameworkCore.Test
{
    public class IntegrationTestFixture : IDisposable
    {
        private readonly TestServer _server;

        public IntegrationTestFixture()
        {
            var contentRoot = Path.Combine("..", "..", "..", "..", "WebSites", "TestSite");

            var builder = new WebHostBuilder()
                .UseContentRoot(contentRoot)
                .ConfigureServices(InitializeServices)
                .UseStartup(typeof(TestSite.Startup));

            _server = new TestServer(builder);

            Client = _server.CreateClient();
            Client.BaseAddress = new Uri("http://localhost");
        }

        public HttpClient Client { get; }

        public void Dispose()
        {
            Client.Dispose();
            _server.Dispose();
        }

        protected void InitializeServices(IServiceCollection services)
        {
            var authenticatorService = new Mock<IAuthenticatorService>(MockBehavior.Strict);

            authenticatorService
                .Setup(a => a.GetCode(HashAlgorithmType.SHA1, It.Is<byte[]>(b=>Encoding.UTF8.GetString(b) == "$3CR3T"), 6, 30))
                .Returns(123456)
                .Verifiable();

            services.AddSingleton<IAuthenticatorService>(authenticatorService.Object);

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseInMemoryDatabase())
                .AddEntityFrameworkInMemoryDatabase();

            services.AddIdentity<AuthenticatorUser<int>, IdentityRole<int>>()
                .AddEntityFrameworkStores<ApplicationDbContext, int>()
                .AddDefaultTokenProviders()
                .AddAuthenticatorEntityFrameworkStore<ApplicationDbContext, int>()
                .AddAuthenticator(c =>
                {
                    c.Issuer = "TestWebAppIdentity";
                });

            services.AddMvc();
        }
    }
}
