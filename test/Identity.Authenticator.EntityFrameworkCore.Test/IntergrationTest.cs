#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace PaulMiami.AspNetCore.Identity.Authenticator.EntityFrameworkCore.Test
{
    public class IntergrationTest : IClassFixture<IntegrationTestFixture>
    {
        public IntergrationTest(IntegrationTestFixture fixture)
        {
            Client = fixture.Client;
        }
        public HttpClient Client { get; }

        [Fact]
        public async Task CreateUserAndAddAuthenticator()
        {
            var formParams = new Dictionary<string, string>();
            formParams["username"] = "john";
            formParams["password"] = "P@$$w0rd";
            formParams["code"] = "123456";
            formParams["hashAlgorithm"] = "SHA1";
            formParams["numberOfDigits"] = "6";
            formParams["periodInSeconds"] = "30";
            formParams["secret"] = "$3CR3T";

            var response = await Client.PostAsync("http://localhost/home/login", new FormUrlEncodedContent(formParams));

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("OK", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task BadCodeCreateUserAndAddAuthenticator()
        {
            var formParams = new Dictionary<string, string>();
            formParams["username"] = "john2";
            formParams["password"] = "P@$$w0rd";
            formParams["code"] = "875654";
            formParams["hashAlgorithm"] = "SHA1";
            formParams["numberOfDigits"] = "6";
            formParams["periodInSeconds"] = "30";
            formParams["secret"] = "$3CR3T";

            var response = await Client.PostAsync("http://localhost/home/login", new FormUrlEncodedContent(formParams));

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("BADCODE", await response.Content.ReadAsStringAsync());
        }
    }
}
