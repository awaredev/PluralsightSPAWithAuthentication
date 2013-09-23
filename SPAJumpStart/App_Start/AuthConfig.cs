using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Web.WebPages.OAuth;
using CodeCamper.Models;
using WebMatrix.WebData;

namespace AuthApplication
{
    public static class AuthConfig
    {
        public static void RegisterAuth()
        {
            //MVC-AUTHENTICATION CODE
            // The Initialization attribute on the Account COntroller would not work under MVC Web-API. Calling Initializer here.
            WebSecurity.InitializeDatabaseConnection("CodeCamper", "UserProfile", "UserId", "UserName", autoCreateTables: true);
            // To let users of this site log in using their accounts from other sites such as Microsoft, Facebook, and Twitter,
            // you must update this site. For more information visit http://go.microsoft.com/fwlink/?LinkID=252166

            //OAuthWebSecurity.RegisterMicrosoftClient(
            //    clientId: "",
            //    clientSecret: "");

            //OAuthWebSecurity.RegisterTwitterClient(
            //    consumerKey: "",
            //    consumerSecret: "");

            //OAuthWebSecurity.RegisterFacebookClient(
            //    appId: "",
            //    appSecret: "");

            //OAuthWebSecurity.RegisterGoogleClient();
        }
    }
}
