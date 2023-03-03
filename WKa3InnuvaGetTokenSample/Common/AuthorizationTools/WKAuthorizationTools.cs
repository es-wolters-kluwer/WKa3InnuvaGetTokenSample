using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http.Extensions;
using System.Security.Claims;
using WKa3InnuvaGetTokenSample.Models.WKIdentity;

namespace WKa3InnuvaGetTokenSample
{
    public class WKAuthorizationTools
    {
        public async Task<WKProcessAuthorizationCodeResult> ProcessAuthorizationCodeAsync(
            AuthorizationCodeReceivedContext context, string baseUrl, string clientId, string clientSecret)
        {

            var discoveryDocument = await GetDiscoveryDocument(baseUrl);
            var claims = new List<Claim>(from c in context.Principal.Claims
                                         where c.Type != "iss" &&
                                               c.Type != "aud" &&
                                               c.Type != "nbf" &&
                                               c.Type != "exp" &&
                                               c.Type != "iat" &&
                                               c.Type != "nonce" &&
                                               c.Type != "c_hash" &&
                                               c.Type != "at_hash"
                                         select c);

            // get userinfo data
            var httpClient = new HttpClient();
            var userInfoRequest = new UserInfoRequest
            {
                Address = baseUrl + "/connect/userinfo",
                Token = context.ProtocolMessage.AccessToken               
                
            };

            var userInfo = await httpClient.GetUserInfoAsync(userInfoRequest).ConfigureAwait(true);
            userInfo.Claims.ToList().ForEach(ui => claims.Add(new Claim(ui.Type, ui.Value)));

            // get access and refresh token
            var request = context.HttpContext.Request;
            var currentUri = UriHelper.BuildAbsolute(request.Scheme, request.Host, request.PathBase, request.Path);
            var authRequest = new AuthorizationCodeTokenRequest
            {
                RedirectUri = currentUri,
                ClientId = clientId,
                ClientSecret = clientSecret,
                Address = discoveryDocument.TokenEndpoint,
                Code = context.ProtocolMessage.Code,
                ClientCredentialStyle = ClientCredentialStyle.PostBody
            };

            var response = await httpClient.RequestAuthorizationCodeTokenAsync(authRequest).ConfigureAwait(true);

            context.HandleCodeRedemption(response.AccessToken, context.ProtocolMessage.IdToken);
            return new WKProcessAuthorizationCodeResult()
            {
                Claims = claims,
                AccessTokenResponse = response,
            };
        }

        private async Task<DiscoveryDocumentResponse> GetDiscoveryDocument(string baseUrl)
        {

            using (var httpClient = new HttpClient())
            {

                var request = new DiscoveryDocumentRequest()
                {
                    Address = baseUrl,
                    Policy = new DiscoveryPolicy()
                    {
                        ValidateIssuerName = false
                    }
                };

                var discoveryDocumentResponse = await httpClient.GetDiscoveryDocumentAsync(request);

                if (discoveryDocumentResponse.IsError)
                {
                    throw new Exception("");
                }
                return discoveryDocumentResponse;
            }

        }
    }
}
