namespace WKa3InnuvaGetTokenSample
{
    public class WKOAuthClientConfigurationModel
    {

        public string? Authority { get; set; }

        public string? AuthorizeEndPoint { get; set; }

        public string? TokenEndPoint { get; set; }

        public string? ClientId { get; set; }

        public string? ClientSecret { get; set; }

        public string? AuthenticationScopes { get; set; }

        public string[] Scopes => string.IsNullOrEmpty(this.AuthenticationScopes) ? new string[] { } : this.AuthenticationScopes.Split("+");

        public string? ResponseType { get; set; }

        public string? AuthenticationType { get; set; }

        public string? RedirectUrl { get; set; }        

    }
}
