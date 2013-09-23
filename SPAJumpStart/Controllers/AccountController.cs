using System;
using System.Collections.Generic;
using System.Linq;
using System.Transactions;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Security;
using CodeCamper.Controllers;
using CodeCamper.Filters;
using DotNetOpenAuth.AspNet;
using Microsoft.Web.WebPages.OAuth;
using WebMatrix.WebData;
using AuthApplication.Filters;
using CodeCamper.Models;

namespace CodeCamper.Controllers
{

    //MVC-AUTHENTICATION CODE
    //The MVC.Authorize attribute does not work in MVC API apps, thus we use the Http namespace version
    //Inherits APIController as this is a MVC API application (was inheriting Controller)
    //Changed all methods to return JsonResults as MVC API sends data, not Views
    [System.Web.Http.Authorize]
    public class AccountController : ApiController
    {

        //New method so SPA can check authentication
        [System.Web.Http.AllowAnonymous]
        [System.Web.Mvc.HttpPost]
        public JsonResult JsonIsAuthorized()
        {
            return new JsonResult { Data = new { Authorized = User.Identity.IsAuthenticated, Name = User.Identity.Name } };
        }

        [System.Web.Http.AllowAnonymous]
        [System.Web.Mvc.HttpPost]
        public JsonResult JsonLogin(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                if (WebSecurity.Login(model.UserName, model.Password, persistCookie: model.RememberMe))
                {
                    FormsAuthentication.SetAuthCookie(model.UserName, model.RememberMe);
                    return new JsonResult { Data = new { success = true } };
                }
                else
                {
                    ModelState.AddModelError("", "The user name or password provided is incorrect.");
                }
            }

            // If we got this far, something failed
            return new JsonResult { Data = new { errors = GetErrorsFromModelState() } };
        }

        //
        // POST: /Account/LogOff

        [System.Web.Mvc.HttpPost]
        public JsonResult JsonLogout()
        {
            WebSecurity.Logout();

            return new JsonResult { Data = new { success = true } };
        }

        //
        // POST: /Account/JsonRegister
        [System.Web.Mvc.HttpPost]
        [System.Web.Http.AllowAnonymous]
        public JsonResult JsonRegister(RegisterModel model)
        {
            //var model = new RegisterModel() { UserName = userName , Password = password, ConfirmPassword = confirmPassword};

            if (ModelState.IsValid)
            {
                // Attempt to register the user
                try
                {
                    WebSecurity.CreateUserAndAccount(model.UserName, model.Password);
                    WebSecurity.Login(model.UserName, model.Password);

                    FormsAuthentication.SetAuthCookie(model.UserName, createPersistentCookie: false);
                    return new JsonResult { Data = new { success = true} };
                }
                catch (MembershipCreateUserException e)
                {
                    ModelState.AddModelError("", ErrorCodeToString(e.StatusCode));
                }
            }

            // If we got this far, something failed
            return new JsonResult { Data = new { errors = GetErrorsFromModelState() } };
        }

        //
        // POST: /Account/Disassociate

        [System.Web.Mvc.HttpPost]
        public JsonResult Disassociate(string provider, string providerUserId)
        {
            string ownerAccount = OAuthWebSecurity.GetUserName(provider, providerUserId);
            ManageMessageId? message = null;

            // Only disassociate the account if the currently logged in user is the owner
            if (ownerAccount == User.Identity.Name)
            {
                // Use a transaction to prevent the user from deleting their last login credential
                using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.Serializable }))
                {
                    bool hasLocalAccount = OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
                    if (hasLocalAccount || OAuthWebSecurity.GetAccountsFromUserName(User.Identity.Name).Count > 1)
                    {
                        OAuthWebSecurity.DeleteAccount(provider, providerUserId);
                        scope.Complete();
                        message = ManageMessageId.RemoveLoginSuccess;
                    }
                }
            }
            return new JsonResult { Data = new { Message = message } };
        }

        //
        // GET: /Account/Manage

        public JsonResult Manage(ManageMessageId? message)
        {
            var statusMessage =
                message == AccountController.ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
                : message == AccountController.ManageMessageId.SetPasswordSuccess ? "Your password has been set."
                : message == AccountController.ManageMessageId.RemoveLoginSuccess ? "The external login was removed."
                : "";
            var hasLocalPassword = OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));

            return new JsonResult { Data = new { Message = statusMessage, HasLocalPassword = hasLocalPassword } };
        }

        //
        // POST: /Account/Manage

        [System.Web.Mvc.HttpPost]
        public JsonResult Manage(LocalPasswordModel model)
        {
            bool hasLocalAccount = OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
            //ViewBag.HasLocalPassword = hasLocalAccount;
            //ViewBag.ReturnUrl = Url.Action("Manage");
            if (hasLocalAccount)
            {
                if (ModelState.IsValid)
                {
                    // ChangePassword will throw an exception rather than return false in certain failure scenarios.
                    bool changePasswordSucceeded;
                    try
                    {
                        changePasswordSucceeded = WebSecurity.ChangePassword(User.Identity.Name, model.OldPassword, model.NewPassword);
                    }
                    catch (Exception)
                    {
                        changePasswordSucceeded = false;
                    }

                    if (changePasswordSucceeded)
                    {
                        return new JsonResult{Data = new { Message = AccountController.ManageMessageId.ChangePasswordSuccess }};
                    }
                    else
                    {
                        ModelState.AddModelError("", "The current password is incorrect or the new password is invalid.");
                    }
                }
            }
            else
            {
                // User does not have a local password so remove any validation errors caused by a missing
                // OldPassword field
                ModelState state = null;//ModelState["OldPassword"];
                if (state != null)
                {
                    state.Errors.Clear();
                }

                if (ModelState.IsValid)
                {
                    try
                    {
                        WebSecurity.CreateAccount(User.Identity.Name, model.NewPassword);
                        return new JsonResult { Data = new { Message = ManageMessageId.SetPasswordSuccess } };
                    }
                    catch (Exception e)
                    {
                        ModelState.AddModelError("", e);
                    }
                }
            }

            // If we got this far, something failed, redisplay form
            return new JsonResult {Data = model};
        }

        //
        // POST: /Account/ExternalLogin

        [System.Web.Mvc.HttpPost]
        [System.Web.Http.AllowAnonymous]
        public JsonResult ExternalLogin(string provider, string returnUrl)
        {
            //Not Implemented- 
            return new JsonResult { Data = new ExternalLoginResult(provider, Url.Route("ExternalLoginCallback", new { ReturnUrl = returnUrl })) };
        }

        //
        // GET: /Account/ExternalLoginCallback

        [System.Web.Http.AllowAnonymous]
        public JsonResult ExternalLoginCallback(string returnUrl)
        {
            AuthenticationResult result = OAuthWebSecurity.VerifyAuthentication(Url.Route("ExternalLoginCallback", new { ReturnUrl = returnUrl }));
            if (!result.IsSuccessful)
            {
                return ExternalLoginFailure();
            }

            if (OAuthWebSecurity.Login(result.Provider, result.ProviderUserId, createPersistentCookie: false))
            {
                return new JsonResult { Data = new { success = true} };
            }

            if (User.Identity.IsAuthenticated)
            {
                // If the current user is logged in add the new account
                OAuthWebSecurity.CreateOrUpdateAccount(result.Provider, result.ProviderUserId, User.Identity.Name);
                return new JsonResult { Data = new { success = true } };
            }
            else
            {
                // User is new, ask for their desired membership name
                string loginData = OAuthWebSecurity.SerializeProviderUserId(result.Provider, result.ProviderUserId);
                //ViewBag.ProviderDisplayName = OAuthWebSecurity.GetOAuthClientData(result.Provider).DisplayName;
                //ViewBag.ReturnUrl = returnUrl;
                return ExternalLoginConfirmation( new RegisterExternalLoginModel { UserName = result.UserName, ExternalLoginData = loginData },"");
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation

        [System.Web.Mvc.HttpPost]
        [System.Web.Http.AllowAnonymous]
        public JsonResult ExternalLoginConfirmation(RegisterExternalLoginModel model, string returnUrl)
        {
            string provider = null;
            string providerUserId = null;

            if (User.Identity.IsAuthenticated || !OAuthWebSecurity.TryDeserializeProviderUserId(model.ExternalLoginData, out provider, out providerUserId))
            {
                return new JsonResult { Data = new { success = true} };
            }

            if (ModelState.IsValid)
            {
                // Insert a new user into the database
                using (UsersContext db = new UsersContext())
                {
                    UserProfile user = db.UserProfiles.FirstOrDefault(u => u.UserName.ToLower() == model.UserName.ToLower());
                    // Check if user already exists
                    if (user == null)
                    {
                        // Insert name into the profile table
                        db.UserProfiles.Add(new UserProfile { UserName = model.UserName });
                        db.SaveChanges();

                        //InitiateDatabaseForNewUser(model.UserName);

                        OAuthWebSecurity.CreateOrUpdateAccount(provider, providerUserId, model.UserName);
                        OAuthWebSecurity.Login(provider, providerUserId, createPersistentCookie: false);

                        return new JsonResult { Data = new { success = true} };
                    }
                    else
                    {
                        ModelState.AddModelError("UserName", "User name already exists. Please enter a different user name.");
                    }
                }
            }

            var providerDisplayName = OAuthWebSecurity.GetOAuthClientData(provider).DisplayName;
            //ViewBag.ReturnUrl = returnUrl;
            return new JsonResult { Data = new { ProviderDisplayName = providerDisplayName} };
        }

        //
        // GET: /Account/ExternalLoginFailure

        [System.Web.Http.AllowAnonymous]
        public JsonResult ExternalLoginFailure()
        {
            return new JsonResult { Data = new { success = false } };
        }

        [System.Web.Http.AllowAnonymous]
        [ChildActionOnly]
        public JsonResult ExternalLoginsList(string returnUrl)
        {
            //ViewBag.ReturnUrl = returnUrl;
            return new JsonResult {Data = new {externalLogins = OAuthWebSecurity.RegisteredClientData}};
        }

        [ChildActionOnly]
        public JsonResult RemoveExternalLogins()
        {
            ICollection<OAuthAccount> accounts = OAuthWebSecurity.GetAccountsFromUserName(User.Identity.Name);
            List<ExternalLogin> externalLogins = new List<ExternalLogin>();
            foreach (OAuthAccount account in accounts)
            {
                AuthenticationClientData clientData = OAuthWebSecurity.GetOAuthClientData(account.Provider);

                externalLogins.Add(new ExternalLogin
                {
                    Provider = account.Provider,
                    ProviderDisplayName = clientData.DisplayName,
                    ProviderUserId = account.ProviderUserId,
                });
            }

            return new JsonResult { Data = externalLogins };
        }

        #region Helpers
       
        public enum ManageMessageId
        {
            ChangePasswordSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
        }

        internal class ExternalLoginResult : ActionResult
        {
            public ExternalLoginResult(string provider, string returnUrl)
            {
                Provider = provider;
                ReturnUrl = returnUrl;
            }

            public string Provider { get; private set; }
            public string ReturnUrl { get; private set; }

            public override void ExecuteResult(ControllerContext context)
            {
                OAuthWebSecurity.RequestAuthentication(Provider, ReturnUrl);
            }
        }

        private IEnumerable<string> GetErrorsFromModelState()
        {
            return ModelState.SelectMany(x => x.Value.Errors.Select(error => error.ErrorMessage));
        }

        private static string ErrorCodeToString(MembershipCreateStatus createStatus)
        {
            // See http://go.microsoft.com/fwlink/?LinkID=177550 for
            // a full list of status codes.
            switch (createStatus)
            {
                case MembershipCreateStatus.DuplicateUserName:
                    return "User name already exists. Please enter a different user name.";

                case MembershipCreateStatus.DuplicateEmail:
                    return "A user name for that e-mail address already exists. Please enter a different e-mail address.";

                case MembershipCreateStatus.InvalidPassword:
                    return "The password provided is invalid. Please enter a valid password value.";

                case MembershipCreateStatus.InvalidEmail:
                    return "The e-mail address provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidAnswer:
                    return "The password retrieval answer provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidQuestion:
                    return "The password retrieval question provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidUserName:
                    return "The user name provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.ProviderError:
                    return "The authentication provider returned an error. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                case MembershipCreateStatus.UserRejected:
                    return "The user creation request has been canceled. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                default:
                    return "An unknown error occurred. Please verify your entry and try again. If the problem persists, please contact your system administrator.";
            }
        }
        #endregion
    }
}