using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Configuration;
using Microsoft.Owin.Security.Notifications;
using System.Threading.Tasks;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Web;
using System;
using Microsoft.Identity.Client;
using System.Data.SqlClient;

namespace Contoso.AzureAD
{
    public partial class Startup
    {
        // Get the values from the web.config file
        private static string tenantId = ConfigurationManager.AppSettings["AAD-TenantId"];
        private static string clientId = ConfigurationManager.AppSettings["AAD-ClientId"];
        private static string postLogoutRedirectUri = ConfigurationManager.AppSettings["AAD-PostLogoutRedirectUriComplete"];
        private static string aadInstance = ConfigurationManager.AppSettings["AAD-AuthorityInstance"];
        private static string authority = aadInstance + tenantId + "/v2.0";
        private static string aadScopes = ConfigurationManager.AppSettings["AAD-AppScopes"];
        private static string msGraphScope = ConfigurationManager.AppSettings["AAD-MSGrapshScopes"];
        private static string redirectUri = postLogoutRedirectUri;

        /// <summary>
        /// This method is called to configure the authentication process.
        /// </summary>
        /// <param name="app"></param>
        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = clientId,
                    Authority = authority,
                    Scope = $"{aadScopes} {msGraphScope}",
                    RedirectUri = redirectUri,
                    PostLogoutRedirectUri = postLogoutRedirectUri,
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        SecurityTokenValidated = (context) =>
                        {
                            // Get the user's email from claims
                            string email = context.AuthenticationTicket.Identity.FindFirst("preferred_username").Value;

                            // Get the user's name from claims
                            string name = context.AuthenticationTicket.Identity.FindFirst("name").Value;

                            // Add the value to the name claim
                            context.AuthenticationTicket.Identity.AddClaim(new Claim(ClaimTypes.Name, name + "(" + email + ")!", string.Empty));

                            return System.Threading.Tasks.Task.FromResult(0);
                        },
                        AuthenticationFailed = OnAuthenticationFailedAsync,
                        AuthorizationCodeReceived = OnAuthorizationCodeReceivedAsync
                    }
                });

        }


        /// <summary>
        /// This method is called if the OpenIdConnect authentication process fails.
        /// </summary>
        /// <param name="notification"></param>
        /// <returns></returns>
        private static Task OnAuthenticationFailedAsync(AuthenticationFailedNotification<OpenIdConnectMessage,
            OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            string redirect = $"/Home/Error?message={notification.Exception.Message}";
            if (notification.ProtocolMessage != null && !string.IsNullOrEmpty(notification.ProtocolMessage.ErrorDescription))
            {
                redirect += $"&debug={notification.ProtocolMessage.ErrorDescription}";
            }
            notification.Response.Redirect(redirect);
            return Task.FromResult(0);
        }

        /// <summary>
        /// This method is called when the authorization code is received.
        /// </summary>
        /// <param name="notification"></param>
        /// <returns></returns>
        private async Task OnAuthorizationCodeReceivedAsync(AuthorizationCodeReceivedNotification notification)
        {
            notification.HandleCodeRedemption();

            var httpContext = notification.OwinContext.Environment["System.Web.HttpContextBase"] as HttpContextBase;

            try
            {
                // You can write logic here to decide who can sign in based on the groups assigned to the user.
                
                bool isAuthorized = true;
                if (httpContext != null)
                {
                    
                    httpContext.Session["IsAuthorized"] = isAuthorized;
                    HttpCookieCollection _cols =  httpContext.Request.Cookies;
                    foreach(string _str in _cols.AllKeys) 
                    {
                        System.Diagnostics.Debug.WriteLine(_str+":->"+_cols.Get(_str).Value);
                    }
                    System.Diagnostics.Debug.WriteLine(notification.JwtSecurityToken);
                    /*var result = httpContext.Request.GetOwinContext().Authentication.AuthenticateAsync("Cookies").GetAwaiter().GetResult();
                    string idToken = result.Properties.Dictionary["id_token"];
                    string accessToken = result.Properties.Dictionary["access_token"];*/
                }

                if (!isAuthorized)
                {
                    throw new UnauthorizedAccessException("You are not part of the required group.");
                }
                notification.HandleCodeRedemption(null);
            }
            catch (MsalException ex)
            {
                string message = "AcquireTokenByAuthorizationCodeAsync threw an exception";
                notification.HandleResponse();
                notification.Response.Redirect($"/Home/Error?message={message}&debug={ex.Message}");
            }
            catch (UnauthorizedAccessException ex)
            {
                // Log the exception
                // Redirect to the error page with a custom message
                notification.HandleResponse();
                notification.OwinContext.Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);

                var urlHelper = new System.Web.Mvc.UrlHelper(httpContext.Request.RequestContext);
                string callbackUrl = urlHelper.Action("Error", "Home", new { message = ex.Message }, httpContext.Request.Url.Scheme);
                notification.Response.Redirect(callbackUrl);
                return;
            }
        }
    }
}