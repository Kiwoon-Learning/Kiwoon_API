using System;
using System.Collections.Generic;
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
    public class LoginsReceiver : BackgroundService
    {
        private readonly IServiceScopeFactory _factory;
        private readonly ServiceBusClient _client;
        private readonly ILogger<LoginsReceiver> _logger;

        public LoginsReceiver(IServiceScopeFactory factory, ServiceBusClient client, ILogger<LoginsReceiver> logger)
        {
            _factory = factory;
            _client = client;
            _logger = logger;
        }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await using var addLoginReceiver = _client.CreateSessionProcessor("AddLogin");
            await using var getLoginsReceiver = _client.CreateSessionProcessor("GetLogins");
            await using var removeLoginReceiver = _client.CreateSessionProcessor("RemoveLogin");
            addLoginReceiver.ProcessMessageAsync += AddLoginReceiveMessageAsync;
            addLoginReceiver.ProcessErrorAsync += args => throw args.Exception;
            getLoginsReceiver.ProcessMessageAsync += GetLoginsReceiveMessageAsync;
            getLoginsReceiver.ProcessErrorAsync += args => throw args.Exception;
            removeLoginReceiver.ProcessMessageAsync += RemoveLoginReceiveMessageAsync;
            removeLoginReceiver.ProcessErrorAsync += args => throw args.Exception;
            await addLoginReceiver.StartProcessingAsync(stoppingToken);
            await getLoginsReceiver.StartProcessingAsync(stoppingToken);
            await removeLoginReceiver.StartProcessingAsync(stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
                await Task.Delay(1000, stoppingToken);
        }

        private async Task AddLoginReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserLoginStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<LoginRequest>();
            try
            {
                await store.AddLoginAsync(request.User, request.Login, arg.CancellationToken);
            }
            catch(Exception e)
            {
                _logger.LogError(e, "Error in AddLogin worker", arg);
            }
            
        }
        private async Task GetLoginsReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserLoginStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<LoginRequest>();
            IList<UserLoginInfo> logins = new List<UserLoginInfo>();
            try
            {
                logins = await store.GetLoginsAsync(request.User, arg.CancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogError(e,"Error in GetLogins worker", arg);
            }

            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(logins))
            {
                SessionId = arg.Message.SessionId
            };
            await sender.SendMessageAsync(response);
        }
        private async Task RemoveLoginReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserLoginStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<LoginRequest>();
            try
            {
                await store.RemoveLoginAsync(request.User, request.Login.LoginProvider, request.Login.ProviderKey, arg.CancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error in RemoveLogin worker", arg);
            }
            
        }
    }
}
