using Microsoft.AspNetCore.Mvc;
using PaulMiami.AspNetCore.Authentication.Authenticator;
using System.Text;

namespace TestWebApp.Controllers
{
    [Route("api/[controller]")]
    public class AuthenticatorController : Controller
    {
        private IAuthenticatorService _service;

        public AuthenticatorController(IAuthenticatorService service)
        {
            _service = service;
        }

        [HttpGet]
        public IActionResult Get(string secret)
        {
            if(string.IsNullOrEmpty(secret))
                return BadRequest();

            return new ObjectResult(string.Format("{0:000000}", _service.GetCode(HashAlgorithmType.SHA1, Encoding.UTF8.GetBytes(secret), 6, 30)));
        }

        
    }
}
