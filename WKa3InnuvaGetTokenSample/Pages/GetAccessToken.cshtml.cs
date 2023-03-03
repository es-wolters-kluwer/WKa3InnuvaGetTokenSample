using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Globalization;
using System.Security.Claims;

namespace WKa3InnuvaGetTokenSample.Pages
{
    [Authorize]
    public class GetAccessTokenModel : PageModel
    {
        public string? ClientId { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public string? AccessTokenExpiration { get; set; }
        public string? AuthenticationDateTime { get; set; }
        public string? Name { get; set; }
        public string? WKIdCDA { get; set; }
        public string? WKUserId { get; set; }
        public string? OtherInfo { get; set; }

        public void OnGet()
        {
            //Show Oauth access-token, refresh-token and claims to the user.
            ClientId = User.FindFirstValue("aud");
            AccessToken = User.FindFirstValue("access_token");
            RefreshToken = User.FindFirstValue("refresh_token");
            Name = User.FindFirstValue("comp_display_name");
            AccessTokenExpiration = DateTimeOffset.FromUnixTimeSeconds((long)Convert.ToDouble(User.FindFirstValue("exp"))).DateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'GMT'K", CultureInfo.InvariantCulture);
            AuthenticationDateTime = DateTimeOffset.FromUnixTimeSeconds((long)Convert.ToDouble(User.FindFirstValue("auth_time"))).DateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'GMT'K", CultureInfo.InvariantCulture);
            WKUserId = User.FindFirstValue("wk.es.clientid");
            WKIdCDA = User.FindFirstValue("wk.es.idcda");
            foreach(var claim in User.Claims)
            {
                if (claim.Type == "scope")
                {
                    if (claim.Value == "WK.ES.A3EquipoContex")
                        OtherInfo = String.Format("SecondUserId:{0}, UserId:{1}", User.FindFirstValue("wk.es.secondclientid"), User.FindFirstValue("wk.es.a3equipouserid"));
                    if (claim.Value == "WK.ES.NEWPOL.COR.API")
                        OtherInfo = String.Format("wk.es.keyusercorrelationid:{0}, Modules:{1}", User.FindFirstValue("wk.es.keyusercorrelationid"), User.FindFirstValue("wk.es.modules"));
                }
            }
        }

        public async Task<IActionResult> OnPostLogout()
        {            
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);            
            return Redirect("~/");
        }
    }
}
