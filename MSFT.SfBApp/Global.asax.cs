using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace MSFT.SfBApp
{
    public class MvcApplication : System.Web.HttpApplication
    {
        // public static string proxyServer = "https://localhost:44310";

        public static string proxyServer = "http://sfbtokensvcssi204.azurewebsites.net";
        // public static string proxyServer = "http://localhost/SfBTokenSvcPrototype";

        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }
    }
}
