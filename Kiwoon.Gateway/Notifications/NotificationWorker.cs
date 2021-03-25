using System;
using System.Threading;
using System.Threading.Tasks;
using Azure.Messaging.ServiceBus;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Kiwoon.Gateway.Notifications
{
    public class NotificationWorker : BackgroundService
    {
        private readonly ServiceBusClient _client;
        private readonly IConfiguration _configuration;
        private readonly IHubContext<NotificationHub> _hubContext;
        private readonly ILogger<NotificationWorker> _logger;

        public NotificationWorker(ServiceBusClient client, IConfiguration configuration, 
            IHubContext<NotificationHub> hubContext, ILogger<NotificationWorker> logger)
        {
            _client = client;
            _configuration = configuration;
            _hubContext = hubContext;
            _logger = logger;
        }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await using var processor = _client.CreateSessionProcessor("ApiResponse", _configuration["ApiResponseSub"]);
            
            processor.ProcessMessageAsync += async args =>
            {
                await _hubContext.Clients.User(args.SessionId).SendAsync("ReceiveMessage", args.Message.Body.ToString(),
                    stoppingToken);
            };
            processor.ProcessErrorAsync += args =>
            {
                _logger.LogError(args.Exception, "Error in notifications", args);
                return Task.CompletedTask;
            };

            await processor.StartProcessingAsync(stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(1000, stoppingToken);
            }
        }
    }
}
