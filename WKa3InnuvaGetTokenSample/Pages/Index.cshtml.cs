using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json.Linq;

namespace WKa3InnuvaGetTokenSample.Pages
{    
    public class IndexModel : PageModel
    {
        public string jsonConfiguration { get; set; }
        private readonly IConfiguration _configuration;

        public IndexModel(IConfiguration configuration)
        { 
            _configuration = configuration  ;
        }

        public void OnGet()
        {
            // Get OAuth configuration from appsettings.json only to show it to the user front
            var wkOAuthConfiguration = _configuration.GetSection("WkeOAuthClientConfiguration");
            jsonConfiguration = SerializeIConfiguration(wkOAuthConfiguration).ToString();
        }

        private JToken SerializeIConfiguration(IConfiguration config)
        {
            JObject obj = new JObject();
            foreach (var child in config.GetChildren())
            {
                obj.Add(child.Key, SerializeIConfiguration(child));
            }

            if (!obj.HasValues && config is IConfigurationSection section)
                return new JValue(section.Value);

            return obj;
        }
    }
}