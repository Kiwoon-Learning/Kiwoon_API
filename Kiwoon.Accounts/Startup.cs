using Azure.Messaging.ServiceBus;
using Kiwoon.Accounts.Data;
using Kiwoon.Accounts.Services;
using Kiwoon.Accounts.Workers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SharedModels.Domain.Identity;

namespace Kiwoon.Accounts
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<AccountDbContext>(options =>
            {
                options.UseSqlServer(Configuration["AccountDb"]);
            }, ServiceLifetime.Transient);
            services.AddScoped<IUserStore<ApplicationUser>, UserStore>();
            services.AddScoped<IUserLoginStore<ApplicationUser>, UserStore>();
            services.AddScoped<IUserPasswordStore<ApplicationUser>, UserStore>();
            services.AddScoped<IUserSecurityStampStore<ApplicationUser>, UserStore>();
            services.AddScoped<IUserEmailStore<ApplicationUser>, UserStore>();
            services.AddScoped<IUserTwoFactorStore<ApplicationUser>, UserStore>();
            services.AddScoped<IUserLockoutStore<ApplicationUser>, UserStore>();
            services.AddScoped<IUserClaimStore<ApplicationUser>, UserStore>();
            services.AddSingleton(new ServiceBusClient(Configuration["AzureMQ"]));
            services.AddHostedService<UserReceiver>();
            services.AddHostedService<ClaimsReceiver>();
            services.AddHostedService<UserFinderReceiver>();
            services.AddHostedService<LoginsReceiver>();
        }
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
        }
    }
}
