
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.SessionState;

using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using WebFormsClient.AppCode;
using SameSiteMode = Microsoft.Owin.SameSiteMode;

[assembly: OwinStartup(typeof(WebFormsClient.Startup))]

namespace WebFormsClient
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "cookie",
                SlidingExpiration = true,
                ExpireTimeSpan = TimeSpan.FromMinutes(15),
                CookieSameSite =SameSiteMode.None
            });


            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = AppSettingsHelper.SSO_ClientId,
                Authority = AppSettingsHelper.SSO_Authority,
                RedirectUri = AppSettingsHelper.SSO_RedirectUri,
                Scope = AppSettingsHelper.SSO_Scope,
                SignInAsAuthenticationType = "cookie",
                PostLogoutRedirectUri = AppSettingsHelper.SSO_PostLogoutRedirectUri,
                RequireHttpsMetadata = false,
                UseTokenLifetime = false,
                RedeemCode = true,
                SaveTokens = true,
                ClientSecret = AppSettingsHelper.SSO_ClientSecret,
                ResponseType = AppSettingsHelper.SSO_ResponseType,
                ResponseMode = "query",

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = async n =>
                    {
                        var id = n.AuthenticationTicket.Identity;

                        id.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));
                        id.AddClaim(new Claim("access_token", n.ProtocolMessage.AccessToken));
                        id.AddClaim(new Claim("refresh_token", n.ProtocolMessage.RefreshToken));

                        n.AuthenticationTicket = new AuthenticationTicket(
                               id,
                               n.AuthenticationTicket.Properties);

                    },

                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType == Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectRequestType.Authentication)
                        {
                            // generate code verifier and code challenge
                            var codeVerifier = CryptoRandom.CreateUniqueId(32);

                            string codeChallenge;
                            using (var sha256 = SHA256.Create())
                            {
                                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                                codeChallenge = IdentityModel.Base64Url.Encode(challengeBytes);
                            }

                            // set code_challenge parameter on authorization request
                            n.ProtocolMessage.SetParameter("code_challenge", codeChallenge);
                            n.ProtocolMessage.SetParameter("code_challenge_method", "S256");

                            // remember code verifier in cookie (adapted from OWIN nonce cookie)
                            // see: https://github.com/scottbrady91/Blog-Example-Classes/blob/master/AspNetFrameworkPkce/ScottBrady91.BlogExampleCode.AspNetPkce/Startup.cs#L85
                            RememberCodeVerifier(n, codeVerifier);
                        }
                        if (n.ProtocolMessage.RequestType == Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectRequestType.Logout)
                        {
                            var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token")?.Value;
                            n.ProtocolMessage.IdTokenHint = idTokenHint;
                        }

                        return System.Threading.Tasks.Task.FromResult(0);
                    },
                    AuthorizationCodeReceived = n =>
                    {
                        // get code verifier from cookie
                        // see: https://github.com/scottbrady91/Blog-Example-Classes/blob/master/AspNetFrameworkPkce/ScottBrady91.BlogExampleCode.AspNetPkce/Startup.cs#L102
                        var codeVerifier = RetrieveCodeVerifier(n);

                        // attach code_verifier on token request
                        n.TokenEndpointRequest.SetParameter("code_verifier", codeVerifier);

                        return System.Threading.Tasks.Task.FromResult(0);
                    },
                    AuthenticationFailed = n =>
                    {
                        return System.Threading.Tasks.Task.FromResult(0);
                    },
                    TokenResponseReceived = n =>
                    {
                        return System.Threading.Tasks.Task.FromResult(0);
                    }
                }
            });

            app.UseStageMarker(PipelineStage.Authenticate);
        }

        private void RememberCodeVerifier(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> n, string codeVerifier)
        {
            var properties = new AuthenticationProperties();
            properties.Dictionary.Add("cv", codeVerifier);
            n.Options.CookieManager.AppendResponseCookie(
                n.OwinContext,
                GetCodeVerifierKey(n.ProtocolMessage.State),
                Convert.ToBase64String(Encoding.UTF8.GetBytes(n.Options.StateDataFormat.Protect(properties))),
                new CookieOptions
                {
                    SameSite = SameSiteMode.None,
                    HttpOnly = true,
                    Secure = n.Request.IsSecure,
                    Expires = DateTime.UtcNow + n.Options.ProtocolValidator.NonceLifetime
                });
        }
        private string RetrieveCodeVerifier(AuthorizationCodeReceivedNotification n)
        {
            string codeVerifier = string.Empty;
            string key = GetCodeVerifierKey(n.ProtocolMessage.State);
            string codeVerifierCookie = n.Options.CookieManager.GetRequestCookie(n.OwinContext, key);
            if (codeVerifierCookie != null)
            {
                var cookieOptions = new CookieOptions
                {
                    SameSite = SameSiteMode.None,
                    HttpOnly = true,
                    Secure = n.Request.IsSecure
                };
                n.Options.CookieManager.DeleteCookie(n.OwinContext, key, cookieOptions);
            }
            var cookieProperties = n.Options.StateDataFormat.Unprotect(Encoding.UTF8.GetString(Convert.FromBase64String(codeVerifierCookie)));
            cookieProperties.Dictionary.TryGetValue("cv", out codeVerifier);

            return codeVerifier;
        }

        private string GetCodeVerifierKey(string state)
        {
            using (var hash = SHA256.Create())
            {
                return OpenIdConnectAuthenticationDefaults.CookiePrefix + "cv." + Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes(state)));
            }
        }
    }
}
