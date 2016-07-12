#region License
//Copyright(c) Paul Biccherai
//Licensed under the MIT license. See LICENSE file in the project root for full license information.
#endregion

namespace PaulMiami.AspNetCore.Authentication.Authenticator
{
    public interface IAuthenticatorService
    {
        string GetUri(string userIdentifier, byte[] secret);

        int GetCode(HashAlgorithmType hashAlgorithm, byte[] secret, byte numberOfDigits, byte periodInSeconds);

        byte PeriodInSeconds { get; }

        byte NumberOfDigits { get; }

        HashAlgorithmType HashAlgorithm { get; }
    }
}
