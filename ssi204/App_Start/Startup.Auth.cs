using System;
using System.Configuration;
using System.Threading.Tasks;
using System.Web;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using SfBTokenSvcPrototype.Models;
using SfBTokenSvcPrototype.Utils;
using Microsoft.Owin.Security.Notifications;
using Microsoft.IdentityModel.Protocols;
using System.IdentityModel.Tokens;
using AuthContext = Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext;

namespace SfBTokenSvcPrototype
{
    public partial class Startup
    {
        //
        // The Client ID is used by the application to uniquely identify itself to Azure AD.
        // The App Key is a credential used to authenticate the application to Azure AD.  Azure AD supports password and certificate credentials.
        // The AAD Instance is the instance of Azure, for example public Azure or Azure China.
        // The Authority is the sign-in URL of the tenant.
        // The Post Logout Redirect Uri is the URL where the user will be redirected after they sign out.
        //

        private ApplicationDbContext db = new ApplicationDbContext();

        public static readonly string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        public static readonly string appKey = ConfigurationManager.AppSettings["ida:AppKey"];
        public static readonly string ucwaResourceUrl = ConfigurationManager.AppSettings["ida:ucwaResourceUrl"];
        public static readonly string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];
        public static readonly string tenantId = ConfigurationManager.AppSettings["ida:TenantId"];
        public static readonly string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        public static readonly string postLogoutRedirectUri = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];
        public static readonly string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static readonly string cacheconnStr = ConfigurationManager.AppSettings["todo:rediscache"];

        public static Microsoft.Owin.Security.Notifications.AuthorizationCodeReceivedNotification LastContext;
        public static string accessToken = string.Empty;
        public static string refreshToken = string.Empty;
        public static string idToken = string.Empty;
        public static string code = string.Empty;
        public static Uri returnUri = null;

        public static string Authority = aadInstance + tenant;
        public static string authority = aadInstance + "common";  // for Multi-Resource Refresh Token

        public static NaiveSessionCache sessionCache = null;

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            // OpenID Connect OWIN Middleware
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    //ClientId = clientId,
                    //Authority = authority,
                    //ResponseType = "code id_token",
                    ClientId = clientId,
                    Authority = authority,
                    PostLogoutRedirectUri = redirectUri,
                    // RedirectUri = redirectUri,
                    TokenValidationParameters = new TokenValidationParameters { SaveSigninToken = true, ValidateIssuer = false },

                    //TokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters
                    //{
                    //    // instead of using the default validation 
                    //    // we inject our own multitenant validation logic, 
                    //    // in addition, this must be set to false as the token service needs to get multi-resource refresh token via code redeem
                    //    ValidateIssuer = false,
                    //},

                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                        SecurityTokenValidated = (context) =>
                        {
                            return Task.FromResult(0);
                        },

                        // The AuthorizationCodeReceived event is invoked only once when authorization really takes place
                        // If auth code is already generated, this event is not invoked
                        // Logout user will force this event to take place

                        //
                        // If there is a code in the OpenID Connect response, redeem it for an access token and refresh token, and store tokens in cache
                        //
                        AuthorizationCodeReceived = OnAuthorizationCodeReceived,

                        //
                        // Handle failed authentication -- incorrect user name/password or diabled/deleted user
                        AuthenticationFailed = OnAuthenticationFailed
                    }
                });
        }

        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            context.HandleResponse();
            context.Response.Redirect("/Home/Error?message=" + context.Exception.Message);
            return Task.FromResult(0);
        }

        // Redeem code for token asynchronosly for performance, must not do synchronous call for Production
        private async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification context)
        {
            Startup.LastContext = context;
            code = context.Code;
            returnUri = new Uri(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path));

            // Token Service appKey is required to authenticate with Azure AD for redeeming the authorization code 
            // Note that the code is returned to LE-SfBApp, but the JavaScript client cannot make use of it
            ClientCredential credential = new ClientCredential(clientId, appKey);

            // userObjectID is the objectGUID of the O365 user in Azure AD
            string userObjectID = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;

            // intialize with common to retrieve MRRT, index Cache with both user GUID and resource url due to UCWA usage pattern
            // Startup.sessionCache = new NaiveSessionCache(userObjectID);
            // Startup.sessionCache = new NaiveSessionCache(userObjectID);
            // Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext authContext = new Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext(Startup.Authority, Startup.sessionCache);
            AuthContext authContext = new AuthContext(Authority,
                    new DistributedTokenCache(cacheconnStr, userObjectID));

            AuthenticationResult result = await authContext.AcquireTokenByAuthorizationCodeAsync(code, returnUri, credential, ucwaResourceUrl);

            // Azure AD schema change
            // string tenantID = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;
            // string signedInUserID = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;
            // AuthenticationContext authContext = new AuthenticationContext(aadInstance + tenantID, new ADALTokenCache(signedInUserID));

            Startup.accessToken = result.AccessToken;
            Startup.refreshToken = result.RefreshToken;
            Startup.idToken = result.IdToken;
        }
    }
}