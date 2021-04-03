using System;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Azure.Messaging.ServiceBus;
using Kiwoon.Core.Authorization;
using Kiwoon.Core.Users;
using Kiwoon.Data;
using Kiwoon.Domain;
using Kiwoon.Domain.Identity;
using Kiwoon.Domain.Identity.Logins;
using Kiwoon.Domain.Identity.Token;
using Kiwoon.Domain.Identity.User;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Kiwoon.Core
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
            services.AddCors(builder =>
                builder.AddDefaultPolicy(policy =>
                {
                    policy.WithOrigins("http://127.0.0.1")
                    .AllowAnyMethod()
                    .SetIsOriginAllowedToAllowWildcardSubdomains()
                    .AllowAnyHeader();
                }));
            services.AddControllers();
            services.AddSignalR();

            services.AddIdentityCore<ApplicationUser>(options => 
                {
                    options.ClaimsIdentity.UserIdClaimType = ClaimTypes.NameIdentifier;
                    options.ClaimsIdentity.EmailClaimType = ClaimTypes.Email;

                    options.Password.RequiredLength = 7;
                    options.Password.RequireDigit = false;
                    options.Password.RequireUppercase = false;
                    options.Password.RequireNonAlphanumeric = false;
                    options.User.RequireUniqueEmail = true;
                })
                .AddDefaultTokenProviders()
                .AddEntityFrameworkStores<AccountDbContext>();

            services.AddTransient<IJwtRepository, JwtRepository>();
            services.AddTransient<IExpiredTokenRepository, ExpiredJwtRepository>();
            services.AddTransient<ITwoFactorTokenRepository, JwtRepository>();
            services.AddTransient<ITwoFactorCodeRepository, LoginRepository>();
            services.AddSingleton<IAuthorizationHandler, JwtUnexpiredHandler>();
            services.AddSingleton<IAuthorizationHandler, CorrectJwtPurposeHandler>();

            services.AddSingleton(new ServiceBusClient(Configuration["AzureMQ"]));
            services.AddTransient<IEmailSender, UserRepository>();
            services.AddTransient<IUserRepository, UserRepository>();
            services.AddScoped<ILoginRepository, LoginRepository>();
            services.AddSingleton<IRateLimitRepository, RateLimitRepository>();

            services.AddStackExchangeRedisCache(options =>
                options.Configuration = Configuration["Redis"]);
            services.AddDbContext<AccountDbContext>(options => 
                options.UseSqlServer(Configuration["AccountDb"]));

            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders =
                    ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            });

            
            services.AddHostedService<UserReceiver>();
            
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = Configuration["JwtIssuer"],
                        ValidAudience = Configuration["JwtAudience"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JwtKey"]))
                    };

                    options.Events = new JwtBearerEvents
                    {
                        OnChallenge = OnAuthChallenge,
                        OnForbidden = OnAuthForbid,
                        OnAuthenticationFailed = OnAuthFailed
                    };
                });

            services.AddAuthorization(options =>
            {
                var unexpiredPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddRequirements(new JwtUnexpiredRequirement(), new CorrectJwtPurposeRequirement())
                    .Build();
                options.DefaultPolicy = unexpiredPolicy;

                options.AddPolicy("TwoFactorEnabled",
                    x => x.RequireClaim(JwtRegisteredClaimNames.Amr, "otp"));
                options.AddPolicy("Admin",
                    policy => policy.RequireClaim("Admin"));
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseForwardedHeaders();

            if (env.IsDevelopment()) app.UseDeveloperExceptionPage();

            app.UseRouting();

            app.Use(UseRateLimit);

            app.UseCors();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }

        public async Task OnAuthChallenge(JwtBearerChallengeContext ctx)
        {
            await ctx.Response.WriteAsJsonAsync(new ApiResponse<string>(false, 401, "Token is invalid"));
            ctx.HandleResponse();
        }

        public async Task OnAuthForbid(ForbiddenContext ctx)
        {
            ctx.Response.StatusCode = 200;
            await ctx.Response.WriteAsJsonAsync(new ApiResponse<string>(false, 403,
                "Token has expired due to a blacklist"));
        }

        public async Task OnAuthFailed(AuthenticationFailedContext ctx)
        {
            ctx.Response.StatusCode = 200;

            if (ctx.Exception is SecurityTokenExpiredException)
            {
                await ctx.Response.WriteAsJsonAsync(new ApiResponse<string>(false, 401, "Token is expired"));
            }
            else if (ctx.Exception is SecurityTokenInvalidSignatureException)
            {
                await ctx.Response.WriteAsJsonAsync(new ApiResponse<string>(false, 401,
                    "Token signature is not valid"));
            }
            else
            {
                Console.WriteLine(ctx.Exception);
                await ctx.Response.WriteAsJsonAsync(new ApiResponse<string>(false, 401,
                    "There was an issue verifying the token"));
            }
        }

        public async Task UseRateLimit(HttpContext context, Func<Task> next)
        {
            var store = context.RequestServices.GetService<IRateLimitRepository>();
            if (store == null)
            {
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new ApiResponse<string>(false, 400, "There was an issue rate limiting this request"));
            }

            var remoteIpAddress = context.Connection.RemoteIpAddress;
            if (remoteIpAddress == null)
            {
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new ApiResponse<string>(false, 400, "User's ip address not found"));
                return;
            }

            var ip = remoteIpAddress.MapToIPv4().ToString();

            await store!.IncrementRequestCount(ip);
            if (await store.GetRequestCountHr(ip) >= 3600 || await store.GetRequestCountMin(ip) >= 10)
            {
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new ApiResponse<string>(false, 429, "Too many requests"));
                return;
            }

            await next();
        }
    }
}