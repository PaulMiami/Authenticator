#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using Xunit;

namespace PaulMiami.AspNetCore.Identity.Authenticator.Test
{
    public class StringExtensionsTest
    {
        [Fact]
        public void NotInt()
        {
            int result;
            Assert.False("fsdgffgf".TryParseAndRemoveWhiteSpace(out result));
            Assert.Equal(0, result);
        }

        [Fact]
        public void Int()
        {
            int result;
            Assert.True("561516".TryParseAndRemoveWhiteSpace(out result));
            Assert.Equal(561516, result);
        }

        [Fact]
        public void IntWithSpace()
        {
            int result;
            Assert.True("6561 5115 1".TryParseAndRemoveWhiteSpace(out result));
            Assert.Equal(656151151, result);
        }

        [Fact]
        public void EmptyString()
        {
            int result;
            Assert.False(string.Empty.TryParseAndRemoveWhiteSpace(out result));
            Assert.Equal(0, result);
        }
    }
}
