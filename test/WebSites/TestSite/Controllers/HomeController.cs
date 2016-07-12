using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using PaulMiami.AspNetCore.Identity.Authenticator;
using PaulMiami.AspNetCore.Identity.Authenticator.EntityFrameworkCore;
using System;
using PaulMiami.AspNetCore.Authentication.Authenticator;
using System.Text;

namespace TestSite.Controllers
{
    public class HomeController : Controller
    {
        private readonly AuthenticatorUserManager<AuthenticatorUser<int>> _userManager;
        private readonly SignInManager<AuthenticatorUser<int>> _signInManager;

        public HomeController(
            AuthenticatorUserManager<AuthenticatorUser<int>> userManager,
            SignInManager<AuthenticatorUser<int>> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpPost]
        public async Task<IActionResult> Login()
        {
            var form = await HttpContext.Request.ReadFormAsync();

            var username = form["username"];
            var password = form["password"];
            var code = form["code"];
            var hashAlgorithm = (HashAlgorithmType)Enum.Parse(typeof(HashAlgorithmType), form["hashAlgorithm"]);
            var numberOfDigits = Convert.ToByte(form["numberOfDigits"]);
            var periodInSeconds = Convert.ToByte(form["periodInSeconds"]);
            var secret = Encoding.UTF8.GetBytes(form["secret"]);

            var user = new AuthenticatorUser<int> { UserName = username };
            await _userManager.CreateAsync(user, password);
            var result = await _userManager.EnableAuthenticatorAsync(user, new Authenticator
            { HashAlgorithm = hashAlgorithm, NumberOfDigits = numberOfDigits, PeriodInSeconds = periodInSeconds, Secret = secret }, code);

            if(result)
                return Content("OK");
            else
                return Content("BADCODE");
        }

        [HttpPost]
        public async Task<IActionResult> Remove()
        {
            var user = await _userManager.GetUserAsync(HttpContext.User);

            var form = await HttpContext.Request.ReadFormAsync();

            var code = form["code"];

            var result = await _userManager.DisableAuthenticatorAsync(user, code);

            if (result)
                return Content("OK");
            else
                return Content("BADCODE");
        }
    }
}
