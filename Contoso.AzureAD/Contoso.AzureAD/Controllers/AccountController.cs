
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Web;
using System.Web.Mvc;

namespace Contoso.AzureAD.Controllers
{
    /// <summary>
    /// This class is responsible for handling the account actions.
    /// </summary>
    public class AccountController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        /// <summary>
        /// This method is called to sign in the user.
        /// </summary>
        [AllowAnonymous]
        public void SignIn()
        {
            if (!Request.IsAuthenticated)
            {

                HttpContext.GetOwinContext()
                    .Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/" },
                        OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
        }

        /// <summary>
        /// This method is called to sign out the user.
        /// </summary>
        /// <param name="message"></param>
        [AllowAnonymous]
        public void SignOut(string message = "")
        {
            string callbackUrl = Url.Action("SignOutCallback", "Account", new { message = message }, protocol: Request.Url.Scheme);

            HttpContext.GetOwinContext().Authentication.SignOut(
                new AuthenticationProperties { RedirectUri = callbackUrl },
                OpenIdConnectAuthenticationDefaults.AuthenticationType, CookieAuthenticationDefaults.AuthenticationType);
        }

        /// <summary>
        /// This method is called when the user is signed out.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public ActionResult SignOutCallback(string message = "")
        {
            ViewBag.Message = message;
            if (Request.IsAuthenticated)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }
    }
}

