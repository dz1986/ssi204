using System;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security;

namespace SfBTokenSvcPrototype.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult SignIn()
        {
            try
            {
                // Send an OpenID Connect sign-in request.
                if (!Request.IsAuthenticated)
                {
                    var url = Url.Action("catchcode", "home");
                    HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = url }, OpenIdConnectAuthenticationDefaults.AuthenticationType);
                }
                return null;
            }
            catch (Exception ex)
            {
                var result = new ContentResult();
                result.Content = ex.ToString();
                return result;
            }
        }

        public void SignOut()
        {
            string callbackUrl = Url.Action("SignOutCallback", "Account", routeValues: null, protocol: Request.Url.Scheme);

            HttpContext.GetOwinContext().Authentication.SignOut(
                new AuthenticationProperties { RedirectUri = callbackUrl },
                OpenIdConnectAuthenticationDefaults.AuthenticationType, CookieAuthenticationDefaults.AuthenticationType);
        }

        public ActionResult SignOutCallback()
        {
            return RedirectToAction("Index", "Home");
        }
    }
}
