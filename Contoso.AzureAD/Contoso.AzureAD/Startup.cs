using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(Contoso.AzureAD.Startup))]
namespace Contoso.AzureAD
{
    public partial class Startup
    {
        /// <summary>
        /// This method is called to configure the authentication process.
        /// </summary>
        /// <param name="app"></param>
        public void Configuration(IAppBuilder app)
        {
            // Configure the OWIN pipeline to use cookie auth.
            ConfigureAuth(app);
        }

    }
}