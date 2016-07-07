#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

using System;

namespace PaulMiami.AspNetCore.Authentication.Authenticator
{
    public static class Base32Encoding
    {
        static readonly char[] EncodingTable = new char[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7' };

        public static string Encode(byte[] input)
        {
            //https://tools.ietf.org/html/rfc4648#page-8
            input.CheckArgumentNull(nameof(input));

            var outputCount = (int)Math.Ceiling((double)input.Length / 5) * 8;
            var output = new char[outputCount];
            var outputIndex = 0;

            for (var i = 0; i < input.Length; i += 5)
            {
                var byteCount = Math.Min(5, input.Length - i);

                ulong buffer = 0;

                for (var j = 0; j < byteCount; j++)
                {
                    buffer = (buffer << 8) | input[i + j];
                }

                var bitCount = byteCount * 8;
                while (bitCount > 0)
                {
                    var index = bitCount >= 5
                                ? (int)(buffer >> (bitCount - 5)) & 0x1f
                                : (int)(buffer & (ulong)(0x1f >> (5 - bitCount))) << (5 - bitCount);

                    output[outputIndex++] = EncodingTable[index];
                    bitCount -= 5;
                }
            }

            while (outputIndex < output.Length)
            {
                output[outputIndex++] = '=';
            }

            return new string(output);
        }
    }
}
