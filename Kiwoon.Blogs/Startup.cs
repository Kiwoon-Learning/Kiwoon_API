using Azure.Messaging.ServiceBus;
using Kiwoon.Blogs.Data;
using Kiwoon.Blogs.Services;
using Kiwoon.Blogs.Workers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SharedModels.Domain.Blog;

namespace Kiwoon.Blogs
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
            services.AddDbContext<BlogDbContext>(options =>
            {
                options.UseSqlServer(Configuration.GetConnectionString("BlogDb"));
            });
            services.AddScoped<IBlogStore, BlogStore>();
            services.AddSingleton(new ServiceBusClient(Configuration.GetConnectionString("AzureMQ")));
            services.AddHostedService<BlogReceiver>();
            services.AddHostedService<FindBlogReceiver>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
        }
    }
}
