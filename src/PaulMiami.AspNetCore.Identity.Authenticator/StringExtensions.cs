#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

namespace PaulMiami.AspNetCore.Identity.Authenticator
{
    public static class StringExtensions
    {
        public static bool TryParseAndRemoveWhiteSpace(this string code, out int result)
        {
            if (!string.IsNullOrEmpty(code))
                code = code.Replace(" ", "");

            return int.TryParse(code, out result);
        }
    }
}
