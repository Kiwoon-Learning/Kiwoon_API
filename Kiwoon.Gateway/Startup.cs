using System;
using System.Security.Claims;
using System.Text;
using Azure.Messaging.ServiceBus;
using Azure.Messaging.ServiceBus.Administration;
using Kiwoon.Gateway.Authorization;
using Kiwoon.Gateway.Domain;
using Kiwoon.Gateway.Domain.Notifications;
using Kiwoon.Gateway.Domain.RateLimit;
using Kiwoon.Gateway.Domain.User;
using Kiwoon.Gateway.Notifications;
using Kiwoon.Gateway.RateLimit;
using Kiwoon.Gateway.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SharedModels.Domain;
using SharedModels.Domain.Blog;
using SharedModels.Domain.Identity;

namespace Kiwoon.Gateway
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
                    policy.AllowAnyOrigin();
                    policy.AllowAnyMethod();
                    policy.AllowAnyHeader();
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
                    options.User.RequireUniqueEmail = true;
                })
                .AddDefaultTokenProviders()
                .AddUserStore<UserStore>();
            services.AddScoped<IJwtStore, JwtStore>();
            services.AddScoped<ITwoFactorStore, TwoFactorStore>();
            services.AddSingleton<IExpiredTokenStore, ExpiredTokenStore>();
            services.AddSingleton(new ServiceBusClient(Configuration["AzureMQ"]));
            services.AddSingleton<IBackgroundTaskQueue, BackgroundTaskQueue>();
            services.AddSingleton<IEmailSender, EmailSender>();
            services.AddSingleton<IRateLimitStore, RateLimitStore>();
            services.AddHostedService<BackgroundQueueWorker>();
            services.AddHostedService<NotificationWorker>();
            services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredUniqueChars = 0;
                options.Tokens.AuthenticatorTokenProvider = "Email";
            });
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
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JwtKey"])),
                    };
                    options.Events = new JwtBearerEvents
                    {
                        OnChallenge = async ctx =>
                        {
                            await ctx.Response.WriteAsJsonAsync(new ApiResponse(false, 401, "Token is invalid"));
                            ctx.HandleResponse();
                        },
                        OnForbidden = async ctx =>
                        {
                            ctx.Response.StatusCode = 200;
                            await ctx.Response.WriteAsJsonAsync(new ApiResponse(false, 403, "Token has expired due to a blacklist"));
                        },
                        OnAuthenticationFailed = async ctx =>
                        {
                            ctx.Response.StatusCode = 200;

                            if (ctx.Exception is SecurityTokenExpiredException)
                            {
                                await ctx.Response.WriteAsJsonAsync(new ApiResponse(false, 401, "Token is expired"));
                            }
                            else if(ctx.Exception is SecurityTokenInvalidSignatureException)
                            {
                                await ctx.Response.WriteAsJsonAsync(new ApiResponse(false, 401, "Token signature is not valid"));
                            }
                            else
                            {
                                await ctx.Response.WriteAsJsonAsync(new ApiResponse(false, 401, "Token is invalid"));
                            }
                        },
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

            options.AddPolicy("Blogger",
                    policy => policy.RequireClaim("Blogger"));
                options.AddPolicy("Admin",
                    policy => policy.RequireClaim("Admin"));
            });
            services.AddSingleton<IAuthorizationHandler, JwtUnexpiredHandler>();
            services.AddSingleton<IAuthorizationHandler, CorrectJwtPurposeHandler>();
            services.AddStackExchangeRedisCache(options => 
                options.Configuration = Configuration["Redis"]);
            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders =
                    ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            });


            var client = new ServiceBusAdministrationClient(Configuration["AzureMQ"]);
            var subName = Guid.NewGuid().ToString();
            Configuration["ApiResponseSub"] = subName;

            if (!client.SubscriptionExistsAsync("ApiResponse", subName).Result)
            {
                client.CreateSubscriptionAsync(new("ApiResponse",subName)
                {
                    AutoDeleteOnIdle = TimeSpan.Zero.Add(TimeSpan.FromMinutes(30)), 
                    RequiresSession = true
                }).Wait();
            }
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseForwardedHeaders();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.Use(async (context, next) =>
            {
                using var scope = context.RequestServices.CreateScope();
                var store = scope.GetNotNullService<IRateLimitStore>();

                var remoteIpAddress = context.Connection.RemoteIpAddress;
                if (remoteIpAddress == null)
                {
                    context.Response.StatusCode = 200;
                    await context.Response.WriteAsJsonAsync(new ApiResponse(false, 400, "User's ip address not found"));
                    return;
                }

                var ip = remoteIpAddress.MapToIPv4().ToString();

                await store.IncrementRequestCount(ip);
                if (await store.GetRequestCountHr(ip) >= 3600 || await store.GetRequestCountMin(ip) >= 10)
                {
                    context.Response.StatusCode = 200;
                    await context.Response.WriteAsJsonAsync(new ApiResponse(false, 429, "Too many requests"));
                    return;
                }

                await next();
            });

            app.UseCors();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapHub<NotificationHub>("/notificationHub");
            });
        }
    }
}
