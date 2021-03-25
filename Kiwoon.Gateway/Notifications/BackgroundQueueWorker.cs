using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Messaging.ServiceBus;
using Kiwoon.Gateway.Domain.Notifications;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Kiwoon.Gateway.Notifications
{
    public class BackgroundQueueWorker : BackgroundService
    {
        private readonly IBackgroundTaskQueue _queue;
        private readonly ILogger<BackgroundQueueWorker> _logger;
        private readonly IServiceScopeFactory _factory;
        private readonly ServiceBusClient _client;

        public BackgroundQueueWorker(IBackgroundTaskQueue queue, ILogger<BackgroundQueueWorker> logger,
            IServiceScopeFactory factory, ServiceBusClient client)
        {
            _queue = queue;
            _logger = logger;
            _factory = factory;
            _client = client;
        }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var job = await _queue.DequeueAsync(stoppingToken);
                using var scope = _factory.CreateScope();
                try
                {
                    var result = await job(scope, stoppingToken);
                    if (result == null) continue;
                    await using var sender = _client.CreateSender("ApiResponse");
                    await sender.SendMessageAsync(new ServiceBusMessage(JsonSerializer.Serialize(result)){SessionId = result.UserId}, stoppingToken);
                }
                catch (Exception e)
                {
                    _logger.LogError(e, $"Error executing {nameof(job)}");
                    throw;
                }
            }
        }
    }
}
