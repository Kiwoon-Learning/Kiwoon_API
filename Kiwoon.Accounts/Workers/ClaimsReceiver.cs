using System;
using System.Collections.Generic;
using System.Linq;
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
    public class ClaimsReceiver : BackgroundService
    {
        private readonly IServiceScopeFactory _factory;
        private readonly ServiceBusClient _client;
        private readonly ILogger<ClaimsReceiver> _logger;

        public ClaimsReceiver(IServiceScopeFactory factory, ServiceBusClient client, ILogger<ClaimsReceiver> logger)
        {
            _factory = factory;
            _client = client;
            _logger = logger;
        }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await using var addClaimsReceiver = _client.CreateSessionProcessor("AddClaims");
            await using var getUsersForClaimReceiver = _client.CreateSessionProcessor("GetUsersForClaim");
            await using var removeClaimsReceiver = _client.CreateSessionProcessor("RemoveClaim");
            await using var replaceClaimReceiver = _client.CreateSessionProcessor("ReplaceClaim");
            await using var getClaimsReceiver = _client.CreateSessionProcessor("GetClaims");

            addClaimsReceiver.ProcessMessageAsync += AddClaimsReceiveMessageAsync;
            addClaimsReceiver.ProcessErrorAsync += args => throw args.Exception;
            getUsersForClaimReceiver.ProcessMessageAsync += GetUsersForClaimReceiveMessageAsync;
            getUsersForClaimReceiver.ProcessErrorAsync += args => throw args.Exception;
            removeClaimsReceiver.ProcessMessageAsync += RemoveClaimsReceiveMessageAsync;
            removeClaimsReceiver.ProcessErrorAsync += args => throw args.Exception;
            replaceClaimReceiver.ProcessMessageAsync += ReplaceClaimReceiveMessageAsync;
            replaceClaimReceiver.ProcessErrorAsync += args => throw args.Exception;
            getClaimsReceiver.ProcessMessageAsync += GetClaimsReceiveMessageAsync;
            getClaimsReceiver.ProcessErrorAsync += args => throw args.Exception;

            await addClaimsReceiver.StartProcessingAsync(stoppingToken);
            await getUsersForClaimReceiver.StartProcessingAsync(stoppingToken);
            await removeClaimsReceiver.StartProcessingAsync(stoppingToken);
            await replaceClaimReceiver.StartProcessingAsync(stoppingToken);
            await getClaimsReceiver.StartProcessingAsync(stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
                await Task.Delay(1000, stoppingToken);
        }

        private async Task AddClaimsReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserClaimStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<ClaimRequest>();
            var claims = from claim in request.Claims
                select claim.ToClaim();
            try
            {
                await store.AddClaimsAsync(request.User, claims, arg.CancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error in AddClaims receiver", arg);
            }
        }
        private async Task RemoveClaimsReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserClaimStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<ClaimRequest>();
            try
            {
                await store.RemoveClaimsAsync(request.User, from claim in request.Claims select claim.ToClaim(), arg.CancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error in RemoveClaims receiver", arg);
            }
        }
        private async Task GetClaimsReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserClaimStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<ClaimRequest>();
            var claims = Enumerable.Empty<ApplicationClaim>();
            try
            {
                claims = from claim in await store.GetClaimsAsync(request.User, arg.CancellationToken)
                         select new ApplicationClaim(claim);
            }
            catch(Exception e)
            {
                _logger.LogError(e, "Error in GetClaims receiver", arg);
            }
            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(claims))
            {
                SessionId = arg.Message.SessionId
            };
            await sender.SendMessageAsync(response);
        }
        private async Task GetUsersForClaimReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserClaimStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<ClaimRequest>();
            IList<ApplicationUser> users = new List<ApplicationUser>();
            try
            {
                users = await store.GetUsersForClaimAsync(request.Claims.ElementAt(0).ToClaim(),
                    arg.CancellationToken);
            }
            catch(Exception e)
            {
                _logger.LogError(e, "Error in GetUsersForClaim receiver",arg);
            }
            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(users))
            {
                SessionId = arg.Message.SessionId
            };
            await sender.SendMessageAsync(response);
        }
        private async Task ReplaceClaimReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IUserClaimStore<ApplicationUser>>();
            var request = arg.Message.Body.ToObjectFromJson<ClaimRequest>();
            try
            {
                await store.ReplaceClaimAsync(request.User, request.Claims.First().ToClaim(),
                    request.Claims.ElementAt(1).ToClaim(), arg.CancellationToken);
            }
            catch(Exception e)
            {
                _logger.LogError(e, "Error in Claims receiver", arg);
            }
        }
    }
}
