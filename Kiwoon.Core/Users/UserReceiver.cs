using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Messaging.ServiceBus;
using Kiwoon.Data;
using Kiwoon.Domain;
using Kiwoon.Domain.Identity;
using Kiwoon.Domain.Identity.Logins;
using Kiwoon.Domain.Identity.User;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace Kiwoon.Core.Users
{
    public class UserReceiver : BackgroundService
    {
        private readonly ServiceBusClient _client;
        private readonly ILogger<UserReceiver> _logger;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly IConfiguration _configuration;

        public UserReceiver(ServiceBusClient client,
            ILogger<UserReceiver> logger, IServiceScopeFactory scopeFactory, IConfiguration configuration)
        {
            _client = client;
            _logger = logger;
            _scopeFactory = scopeFactory;
            _configuration = configuration;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await using var updateUserReceiver = _client.CreateProcessor("UpdateUser");
            await using var deleteUserReceiver = _client.CreateProcessor("DeleteUser");

            await using var addLoginReceiver = _client.CreateProcessor("AddUserLogin");
            await using var removeLoginReceiver = _client.CreateProcessor("RemoveUserLogin");

            await using var emailReceiver = _client.CreateProcessor("SendEmail");

            updateUserReceiver.ProcessMessageAsync += UpdateUserReceiveMessageAsync;
            updateUserReceiver.ProcessErrorAsync += ReturnErrorMessageAsync;
            deleteUserReceiver.ProcessMessageAsync += DeleteUserReceiveMessageAsync;
            deleteUserReceiver.ProcessErrorAsync += ReturnErrorMessageAsync;

            addLoginReceiver.ProcessMessageAsync += AddUserLoginAsync;
            addLoginReceiver.ProcessErrorAsync += ReturnErrorMessageAsync;
            removeLoginReceiver.ProcessMessageAsync += RemoveUserLoginAsync;
            removeLoginReceiver.ProcessErrorAsync += ReturnErrorMessageAsync;

            emailReceiver.ProcessMessageAsync += SendEmailAsync;
            emailReceiver.ProcessErrorAsync += ReturnErrorMessageAsync;

            await updateUserReceiver.StartProcessingAsync(stoppingToken);
            await deleteUserReceiver.StartProcessingAsync(stoppingToken);

            await addLoginReceiver.StartProcessingAsync(stoppingToken);
            await removeLoginReceiver.StartProcessingAsync(stoppingToken);

            await emailReceiver.StartProcessingAsync(stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
                await Task.Delay(1000, stoppingToken);
        }

        private async Task SendEmailAsync(ProcessMessageEventArgs args)
        {
            var request = args.Message.Body.ToObjectFromJson<EmailRequest>();

            var msg = MailHelper.CreateSingleEmail(
                new EmailAddress(_configuration["EmailSender"]),
                new EmailAddress(request.Email),
                request.Subject,
                request.HtmlMessage,
                request.HtmlMessage
            );

            var client = new SendGridClient(_configuration["EmailKey"]);
            var response = await client.SendEmailAsync(msg);
            _logger.LogInformation(JsonSerializer.Serialize(response));
        }

        private async Task RemoveUserLoginAsync(ProcessMessageEventArgs arg)
        {
            using var scope = _scopeFactory.CreateScope();
            var context = scope.GetNotNullService<AccountDbContext>();

            var request = arg.Message.Body.ToObjectFromJson<LoginRequest>();

            context.UserLogins.Remove(new IdentityUserLogin<string>
            {
                UserId = request.User.Id,
                LoginProvider = request.LoginProvider,
                ProviderDisplayName = request.LoginProvider,
                ProviderKey = request.ProviderKey
            });
            await context.SaveChangesAsync();
        }

        private async Task AddUserLoginAsync(ProcessMessageEventArgs arg)
        {
            using var scope = _scopeFactory.CreateScope();
            var context = scope.GetNotNullService<AccountDbContext>();

            var request = arg.Message.Body.ToObjectFromJson<LoginRequest>();

            await context.UserLogins.AddAsync(new IdentityUserLogin<string>
            {
                UserId = request.User.Id,
                LoginProvider = request.LoginProvider,
                ProviderDisplayName = request.LoginProvider,
                ProviderKey = request.ProviderKey
            });
            await context.SaveChangesAsync();
        }

        private async Task UpdateUserReceiveMessageAsync(ProcessMessageEventArgs arg)
        {
            using var scope = _scopeFactory.CreateScope();
            var context = scope.GetNotNullService<AccountDbContext>();

            var request = arg.Message.Body.ToObjectFromJson<UserRequest>();

            context.Update(request.User);
            await context.SaveChangesAsync();
        }

        private async Task DeleteUserReceiveMessageAsync(ProcessMessageEventArgs arg)
        {
            using var scope = _scopeFactory.CreateScope();
            var context = scope.GetNotNullService<AccountDbContext>();

            var request = arg.Message.Body.ToObjectFromJson<UserRequest>();

            context.Users.Remove(request.User);
            await context.SaveChangesAsync();
        }

        private Task ReturnErrorMessageAsync(ProcessErrorEventArgs args)
        {
            _logger.LogError(args.Exception, "Error in service bus receiver", args);
            return Task.CompletedTask;
        }
    }
}