using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace TestWebApp.Models.Home
{
    public class IndexViewModel
    {
        [Required]
        public string Secret { get; set; } = "foobar";

        public string AuthenticatorUri { get; set; }
    }
}
