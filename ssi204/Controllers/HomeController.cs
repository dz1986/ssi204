using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Protocols;
using SfBTokenSvcPrototype.Utils;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace SfBTokenSvcPrototype.Controllers
{
    public class HomeController : Controller
    {
        private static readonly string cacheconnStr = ConfigurationManager.AppSettings["todo:rediscache"];
        // GET: Home
        public ActionResult Index()
        {
            return View();
        }

        public JsonResult GetAccessTokenForNewResource_v0(string id_token, string newResourceUrl)
        {
            /* re-use authroization code
            {
              "aud": "https://webdirca1.online.lync.com",
              "iss": "https://sts.windows.net/46eaa115-a26e-48a3-9ce7-4873bd552df2/",
              "iat": 1465507966, <--‎6‎/‎9‎/‎2016‎ ‎2‎:‎32‎:‎46‎ ‎PM GMT-7:00 DST
              "nbf": 1465507966,
              "exp": 1465511866,
              "acr": "1",
              "amr": [
                "pwd"
              ],
              "appid": "565a2de8-5355-46e6-b0ab-3dadf3ac8e61",
              "appidacr": "1",
              "family_name": "foo",
              "given_name": "ssiprod",
              "ipaddr": "131.107.174.88",
              "name": "ssiprod foo",
              "oid": "c3fa6fd4-3df5-4f14-ac8b-c7b5a0976f7d",
              "puid": "10033FFF97E1DA74",
              "scp": "Contacts.ReadWrite Conversations.Initiate Conversations.Receive Meetings.ReadWrite User.ReadWrite",
              "sub": "co1jUVaOD8kWC-fOnwWvWNeJtG_LrTsrSUK7iBh2mdg",
              "tid": "46eaa115-a26e-48a3-9ce7-4873bd552df2",
              "unique_name": "ssiprodfoo@ssiprodfoo.onmicrosoft.com",
              "upn": "ssiprodfoo@ssiprodfoo.onmicrosoft.com",
              "ver": "1.0"
            } 
            */
            ClientCredential credential = new ClientCredential(Startup.clientId, Startup.appKey);

            string userObjectID = Startup.LastContext.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;

            Uri res = new Uri(newResourceUrl);
            string ucwaResource = res.GetLeftPart(UriPartial.Authority);

            // intialize with common to retrieve MRRT, index Cache with both user GUID and resource url due to ucwa usage pattern
            Startup.sessionCache = new NaiveSessionCache(userObjectID + ucwaResource);
            AuthenticationContext authContext = new AuthenticationContext(Startup.authority, Startup.sessionCache);

            AuthenticationResult result = authContext.AcquireTokenByAuthorizationCode(Startup.code, Startup.returnUri, credential, res.GetLeftPart(UriPartial.Authority));

            // string tenantID = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;
            // string signedInUserID = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;

            // AuthenticationContext authContext = new AuthenticationContext(aadInstance + tenantID, new ADALTokenCache(signedInUserID));
            Startup.accessToken = result.AccessToken;
            Startup.refreshToken = result.RefreshToken;
            Startup.idToken = result.IdToken;

            return Json(new { accessToken = result.AccessToken }, JsonRequestBehavior.AllowGet);
        }

        public async System.Threading.Tasks.Task<JsonResult> GetAccessTokenForNewResource_v1(string id_token, string newResourceUrl)
        {
            /* On-behalf-of flow
            {
              "aud": "https://webdirca1.online.lync.com",
              "iss": "https://sts.windows.net/46eaa115-a26e-48a3-9ce7-4873bd552df2/",
              "iat": 1465507708, <--‎6‎/‎9‎/‎2016‎ ‎2‎:‎28‎:‎28‎ ‎PM GMT-7:00 DST
              "nbf": 1465507708,
              "exp": 1465511608,
              "acr": "1",
              "amr": [
                "pwd"
              ],
              "appid": "565a2de8-5355-46e6-b0ab-3dadf3ac8e61",
              "appidacr": "1",
              "family_name": "foo",
              "given_name": "ssiprod",
              "ipaddr": "131.107.174.88",
              "name": "ssiprod foo",
              "oid": "c3fa6fd4-3df5-4f14-ac8b-c7b5a0976f7d",
              "puid": "10033FFF97E1DA74",
              "scp": "Contacts.ReadWrite Conversations.Initiate Conversations.Receive Meetings.ReadWrite User.ReadWrite",
              "sub": "co1jUVaOD8kWC-fOnwWvWNeJtG_LrTsrSUK7iBh2mdg",
              "tid": "46eaa115-a26e-48a3-9ce7-4873bd552df2",
              "unique_name": "ssiprodfoo@ssiprodfoo.onmicrosoft.com",
              "upn": "ssiprodfoo@ssiprodfoo.onmicrosoft.com",
              "ver": "1.0"
            }
             */
            AuthenticationResult result = null;

            ClientCredential credential = new ClientCredential(Startup.clientId, Startup.appKey);

            // objectGUID of the user in AAD
            string userObjectID = Startup.LastContext.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;

            // string userObjectID = "bbd4b145-b12c-4f0a-914a-e86a6f550458";

            Uri res = new Uri(newResourceUrl);
            string ucwaResource = res.GetLeftPart(UriPartial.Authority);

            // intialize with common to retrieve MRRT, index Cache with both user GUID and resource url due to ucwa usage pattern
            // Startup.sessionCache = new NaiveSessionCache(userObjectID);
            // Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext authContext = new Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext(Startup.Authority, Startup.sessionCache);
            AuthenticationContext authContext = new AuthenticationContext(Startup.Authority,
                new DistributedTokenCache(cacheconnStr, userObjectID));

            result = await authContext.AcquireTokenSilentAsync(ucwaResource, credential, new UserIdentifier(userObjectID, UserIdentifierType.UniqueId));

            // result = authContext.AcquireTokenSilent (ucwaResource, credential, new UserIdentifier(userObjectID, UserIdentifierType.UniqueId));

            return Json(new { accessToken = result.AccessToken }, JsonRequestBehavior.AllowGet);

        }

        public async System.Threading.Tasks.Task<JsonResult> GetAccessTokenForNewResource(string id_token, string newResourceUrl)
        {
            /* User Credential: acr = 0
            {
              "aud": "https://webdirca1.online.lync.com",
              "iss": "https://sts.windows.net/46eaa115-a26e-48a3-9ce7-4873bd552df2/",
              "iat": 1465507798, <--‎6‎/‎9‎/‎2016‎ ‎2‎:‎29‎:‎58‎ ‎PM GMT-7:00 DST
              "nbf": 1465507798,
              "exp": 1465511857,
              "acr": "0",
              "amr": [
                "pwd"
              ],
              "appid": "565a2de8-5355-46e6-b0ab-3dadf3ac8e61",
              "appidacr": "1",
              "family_name": "foo",
              "given_name": "ssiprod",
              "ipaddr": "131.107.174.88",
              "name": "ssiprod foo",
              "oid": "c3fa6fd4-3df5-4f14-ac8b-c7b5a0976f7d",
              "puid": "10033FFF97E1DA74",
              "scp": "Contacts.ReadWrite Conversations.Initiate Conversations.Receive Meetings.ReadWrite User.ReadWrite",
              "sub": "co1jUVaOD8kWC-fOnwWvWNeJtG_LrTsrSUK7iBh2mdg",
              "tid": "46eaa115-a26e-48a3-9ce7-4873bd552df2",
              "unique_name": "ssiprodfoo@ssiprodfoo.onmicrosoft.com",
              "upn": "ssiprodfoo@ssiprodfoo.onmicrosoft.com",
              "ver": "1.0"
             } 
             */

            AuthenticationResult result = null;
            ClientCredential clientCred = new ClientCredential(Startup.clientId, Startup.appKey);

            var bootstrapContext = ClaimsPrincipal.Current.Identities.First().BootstrapContext as System.IdentityModel.Tokens.BootstrapContext;
            string userName = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Upn) != null ? ClaimsPrincipal.Current.FindFirst(ClaimTypes.Upn).Value : ClaimsPrincipal.Current.FindFirst(ClaimTypes.Email).Value;
            string userAccessToken = bootstrapContext.Token;

            UserAssertion userAssertion = new UserAssertion(bootstrapContext.Token, "urn:ietf:params:oauth:grant-type:jwt-bearer", userName);

            string userId = ClaimsPrincipal.Current.FindFirst(ClaimTypes.NameIdentifier).Value;

            AuthenticationContext authContext = new AuthenticationContext(Startup.Authority, new NaiveSessionCache(userId));

            Uri res = new Uri(newResourceUrl);
            string ucwaResource = res.GetLeftPart(UriPartial.Authority);

            result = await authContext.AcquireTokenAsync(ucwaResource, clientCred, userAssertion);

            return Json(new { accessToken = result.AccessToken }, JsonRequestBehavior.AllowGet);

        }

        private static bool isValid(string id_token)
        {
            // as the storage for id_token is a Salesforce component
            return true;
        }

        // this will be called from another Browser client
        // demonstrate that cached access token can be returned from the same user
        public JsonResult GetCachedAccessToken(string u1_prime)
        {
            try
            {
                string accessToken;
                //the same user u1_prime starts using a new browser, it should first re-retieve access token from token storage
                // indexed by u1_prime
                if (u1_prime != string.Empty)
                {
                    accessToken = Startup.accessToken;
                }
                else
                {
                    // this shall never happen, as Salesforce authentication will determine whether u1_prime has an access token or not
                    // if not, LE-SfBApp will always show a sign-in to O365, which will re-direct user to account/signin to authenticate with AAD
                    accessToken = GetNewAccessTokenForNewUser(u1_prime);
                }

                return Json(new { accessToken = accessToken }, JsonRequestBehavior.AllowGet);

            }
            catch (Exception ex)
            {
                return Json(new { err = ex.Message, }, JsonRequestBehavior.AllowGet);
            }
        }

        private static string GetNewAccessTokenForNewUser(string u1_prime)
        {
            throw new NotImplementedException();
        }

        //[HttpPost]
        public ActionResult CatchCode(string code, string id_token, string state, string session_state)
        {
            try
            {
                var context = Startup.LastContext;
                // var accessToken = GetAccessToken(context.Code, this.Request.Url);
                //var result = new RedirectResult(string.Format("http://localhost:42645/Home/GetToken?", accessToken));
                // return Redirect(string.Format("http://localhost:42645/Home/GetToken#token={0}", context.JwtSecurityToken.RawData));
                return Redirect(string.Format("http://localhost:19906/Home/GetToken#token={0}", Startup.accessToken));
            }
            catch (Exception ex)
            {
                return Content(ex.ToString());
            }
        }

        public ContentResult Error()
        {
            var error = Server.GetLastError();
            return Content(error == null ? "No error" : error.ToString());
        }
    }
}