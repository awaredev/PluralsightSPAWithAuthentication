using System;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using AuthApplication;

namespace CodeCamper
{
    public class Global : System.Web.HttpApplication
    {
        protected void Application_Start(object sender, EventArgs e)
        {
            //AreaRegistration.RegisterAllAreas();

            WebApiConfig.Register(GlobalConfiguration.Configuration);
            BundleConfig.RegisterBundles(BundleTable.Bundles);

            //Added these for Authentication, found in MVC SPA App_Start folder
            AuthConfig.RegisterAuth();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
        }
    }
}