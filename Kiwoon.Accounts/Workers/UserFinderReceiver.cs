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
    public class UserFinderReceiver : BackgroundService
    {
        private readonly IServiceScopeFactory _factory;
        private readonly ServiceBusClient _client;
        private readonly ILogger<UserFinderReceiver> _logger;

        public UserFinderReceiver(IServiceScopeFactory factory, ServiceBusClient client, 
            ILogger<UserFinderReceiver> logger)
        {
            _factory = factory;
            _client = client;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await using var findByEmailReceiver = _client.CreateSessionProcessor("FindByEmail");
            await using var findByIdReceiver = _client.CreateSessionProcessor("FindById");
            await using var findByLoginReceiver = _client.CreateSessionProcessor("FindByLogin");
            await using var findByNameReceiver = _client.CreateSessionProcessor("FindByName");
            findByEmailReceiver.ProcessMessageAsync += FindByEmailReceiveMessageAsync;
            findByEmailReceiver.ProcessErrorAsync += args => throw args.Exception;
            findByIdReceiver.ProcessMessageAsync += FindByIdReceiveMessageAsync;
            findByIdReceiver.ProcessErrorAsync += args => throw args.Exception;
            findByLoginReceiver.ProcessMessageAsync += FindByLoginReceiveMessageAsync;
            findByLoginReceiver.ProcessErrorAsync += args => throw args.Exception;
            findByNameReceiver.ProcessMessageAsync += FindByNameReceiveMessageAsync;
            findByNameReceiver.ProcessErrorAsync += args => throw args.Exception;
            await findByEmailReceiver.StartProcessingAsync(stoppingToken);
            await findByIdReceiver.StartProcessingAsync(stoppingToken);
            await findByLoginReceiver.StartProcessingAsync(stoppingToken);
            await findByNameReceiver.StartProcessingAsync(stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
                await Task.Delay(1000, stoppingToken);
        }

        private async Task FindByEmailReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserEmailStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<FindByRequest>();
            ApplicationUser user = new();
            try
            {
                user = await store.FindByEmailAsync(request.SearchQuery, arg.CancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error in FindByEmail worker", arg);
            }

            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(user))
            {
                SessionId = arg.SessionId
            };
            await sender.SendMessageAsync(response);
        }

        private async Task FindByIdReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<FindByRequest>();
            ApplicationUser user = new();
            try
            {
                user = await store.FindByIdAsync(request.SearchQuery, arg.CancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error in FindById worker", arg);
            }

            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(user))
            {
                SessionId = arg.SessionId
            };
            await sender.SendMessageAsync(response);
        }

        private async Task FindByLoginReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserLoginStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<LoginRequest>();
            ApplicationUser user = new();
            try
            {
                user = await store.FindByLoginAsync(request.Login.LoginProvider, request.Login.ProviderKey,
                    arg.CancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error in FindByLogin worker", arg);
            }

            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(user))
            {
                SessionId = arg.SessionId
            };
            await sender.SendMessageAsync(response);
        }

        private async Task FindByNameReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<FindByRequest>();
            ApplicationUser user = new();
            try
            {
                user = await store.FindByNameAsync(request.SearchQuery, arg.CancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error in FindByName worker", arg);
            }

            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(user))
            {
                SessionId = arg.SessionId
            };
            await sender.SendMessageAsync(response);
        }
    }
}