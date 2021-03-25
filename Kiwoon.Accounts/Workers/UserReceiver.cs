using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Messaging.ServiceBus;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SharedModels.Domain.Identity;

namespace Kiwoon.Accounts.Workers
{
    public class UserReceiver : BackgroundService
    {
        private readonly IServiceScopeFactory _factory;
        private readonly ServiceBusClient _client;
        private readonly ILogger<UserReceiver> _logger;

        public UserReceiver(IServiceScopeFactory factory, ServiceBusClient client,
            ILogger<UserReceiver> logger)
        {
            _factory = factory;
            _client = client;
            _logger = logger;
        }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await using var createUserReceiver = _client.CreateSessionProcessor("CreateUser");
            await using var updateUserReceiver = _client.CreateSessionProcessor("UpdateUser");
            await using var deleteUserReceiver = _client.CreateSessionProcessor("DeleteUser");

            createUserReceiver.ProcessMessageAsync += CreateUserReceiveMessageAsync;
            createUserReceiver.ProcessErrorAsync += args => throw args.Exception;
            updateUserReceiver.ProcessMessageAsync += UpdateUserReceiveMessageAsync;
            updateUserReceiver.ProcessErrorAsync += args => throw args.Exception;
            deleteUserReceiver.ProcessMessageAsync += DeleteUserReceiveMessageAsync;
            deleteUserReceiver.ProcessErrorAsync += args => throw args.Exception;

            await createUserReceiver.StartProcessingAsync(stoppingToken);
            await updateUserReceiver.StartProcessingAsync(stoppingToken);
            await deleteUserReceiver.StartProcessingAsync(stoppingToken);
            while (!stoppingToken.IsCancellationRequested)
                await Task.Delay(1000, stoppingToken);
        }

        private async Task CreateUserReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<UserRequest>();
            IdentityResult result = new();
            try
            {
                result = await store.CreateAsync(request.User, arg.CancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error in CreateUser worker", arg);
            }

            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(result))
            {
                SessionId = arg.SessionId
            };
            await sender.SendMessageAsync(response);
        }
        private async Task UpdateUserReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<UserRequest>();
            IdentityResult result = new();
            try
            {
                result = await store.UpdateAsync(request.User, arg.CancellationToken);
            }
            catch(Exception e)
            {
                _logger.LogError(e, "Error in UpdateUser worker", arg);
            }

            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(result))
            {
                SessionId = arg.SessionId
            };
            await sender.SendMessageAsync(response);
        }
        private async Task DeleteUserReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<UserRequest>();
            IdentityResult result = new();
            try
            {
                result = await store.DeleteAsync(request.User, arg.CancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error in DeleteUser worker", arg);
            }

            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(result))
            {
                SessionId = arg.SessionId
            };
            await sender.SendMessageAsync(response);
        }
    }
}
