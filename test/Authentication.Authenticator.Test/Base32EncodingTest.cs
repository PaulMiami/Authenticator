#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using System;
using System.Linq;
using System.Text;
using Xunit;

namespace PaulMiami.AspNetCore.Authentication.Authenticator.Test
{
    public class Base32EncodingTest
    {
        [Fact]
        public void NullInput()
        {
            Assert.Throws<ArgumentNullException>(()=>Base32Encoding.Encode(null));
        }

        [Fact]
        public void TestHello()
        {
            var test = Encoding.UTF8.GetBytes("Hello!").Concat(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }).ToArray();

            Assert.Equal("JBSWY3DPEHPK3PXP", Base32Encoding.Encode(test));
        }

        [Theory]
        [InlineData("","")]
        [InlineData("MY======", "f")]
        [InlineData("MZXQ====", "fo")]
        [InlineData("MZXW6===", "foo")]
        [InlineData("MZXW6YQ=", "foob")]
        [InlineData("MZXW6YTB", "fooba")]
        [InlineData("MZXW6YTBOI======", "foobar")]
        public void MoreTest(string expected, string actual)
        {
            //https://tools.ietf.org/html/rfc4648#section-10
            Assert.Equal(expected, Base32Encoding.Encode(Encoding.UTF8.GetBytes(actual)));
        }
    }
}
