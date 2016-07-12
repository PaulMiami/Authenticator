using Microsoft.AspNetCore.Mvc;
using TestWebApp.Models.Home;
using PaulMiami.AspNetCore.Authentication.Authenticator;
using System.Text;

// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace TestWebApp.Controllers
{
    public class HomeController : Controller
    {
        private IAuthenticatorService _service;

        public HomeController(IAuthenticatorService service)
        {
            _service = service;
        }

        public IActionResult Index()
        {
            var model = new IndexViewModel();
            SetUri(model);
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(IndexViewModel model)
        {
            if (ModelState.IsValid)
            {
                SetUri(model);
                return View(model);
            }

            return View(model);
        }

        private void SetUri(IndexViewModel model)
        {
            model.AuthenticatorUri = _service.GetUri("JohnDoe@gmail.com", Encoding.UTF8.GetBytes(model.Secret));
        }
    }
}
