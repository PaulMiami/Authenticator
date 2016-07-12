using PaulMiami.AspNetCore.Authentication.Authenticator;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace TestWebAppIdentity.Models.ManageViewModels
{
    public class RemoveAuthenticatorViewModel
    {
        [Required]
        public string Code { get; set; }
    }
}
