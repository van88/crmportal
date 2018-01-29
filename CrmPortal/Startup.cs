using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(CrmPortal.Startup))]
namespace CrmPortal
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
