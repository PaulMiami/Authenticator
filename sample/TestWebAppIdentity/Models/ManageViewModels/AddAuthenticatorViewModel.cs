using PaulMiami.AspNetCore.Authentication.Authenticator;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace TestWebAppIdentity.Models.ManageViewModels
{
    public class AddAuthenticatorViewModel
    {
        public string Uri { get; set; }

        public string Secret { get; set; }

        public HashAlgorithmType HashAlgorithm { get; set; }

        public byte NumberOfDigits { get; set; }

        public byte PeriodInSeconds { get; set; }

        [Required]
        public string Code { get; set; }
    }
}
