using Microsoft.AspNetCore.Mvc;
using PaulMiami.AspNetCore.Authentication.Authenticator;
using System.Text;

namespace TestWebApp.Controllers
{
    [Route("api/[controller]")]
    public class AuthenticatorController : Controller
    {
        private AuthenticatorService _service;

        public AuthenticatorController(AuthenticatorService service)
        {
            _service = service;
        }

        [HttpGet]
        public IActionResult Get(string secret)
        {
            if(string.IsNullOrEmpty(secret))
                return BadRequest();

            return new ObjectResult(string.Format("{0:000000}", _service.GetCode(HashAlgorithm.SHA1, Encoding.UTF8.GetBytes(secret), 6, 30)));
        }

        
    }
}
