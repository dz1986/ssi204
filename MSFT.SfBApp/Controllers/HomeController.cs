using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace MSFT.SfBApp.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
        // From http://sfbproxytokensvc.azurewebsites.net
        // To   http://msft2sfbapp20160509074200.azurewebsites.net/Home/GetToken#token=
        public ActionResult GetToken()
        {
            return View();
        }
    }
}