using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Messaging.ServiceBus;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SharedModels.Domain.Blog;

namespace Kiwoon.Blogs.Workers
{
    public class BlogReceiver : BackgroundService
    {

        private readonly IServiceScopeFactory _factory;
        private readonly ServiceBusClient _client;

        public BlogReceiver(IServiceScopeFactory factory, ServiceBusClient client)
        {
            _factory = factory;
            _client = client;
        }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await using var createBlogReceiver = _client.CreateSessionProcessor("CreateBlog");
            await using var updateBlogReceiver = _client.CreateSessionProcessor("UpdateBlog");
            await using var deleteBlogReceiver = _client.CreateSessionProcessor("DeleteBlog");
            createBlogReceiver.ProcessMessageAsync += CreateBlogReceiveMessageAsync;
            createBlogReceiver.ProcessErrorAsync += args => throw args.Exception;
            updateBlogReceiver.ProcessMessageAsync += UpdateBlogReceiveMessageAsync;
            updateBlogReceiver.ProcessErrorAsync += args => throw args.Exception;
            deleteBlogReceiver.ProcessMessageAsync += DeleteBlogReceiveMessageAsync;
            deleteBlogReceiver.ProcessErrorAsync += args => throw args.Exception;
            await createBlogReceiver.StartProcessingAsync(stoppingToken);
            await updateBlogReceiver.StartProcessingAsync(stoppingToken);
            await deleteBlogReceiver.StartProcessingAsync(stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
                await Task.Delay(1000, stoppingToken);
        }

        private async Task CreateBlogReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            BlogResult result;
            using (var scope = _factory.CreateScope())
            {
                var store = scope.ServiceProvider.GetService<IBlogStore>();
                var request = arg.Message.Body.ToObjectFromJson<BlogRequest>();
                result = await store.CreateBlogAsync(request.Blog);
            }

            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(result))
            {
                SessionId = arg.Message.SessionId
            };
            await sender.SendMessageAsync(response);

        }
        private async Task DeleteBlogReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            BlogResult result;
            using (var scope = _factory.CreateScope())
            {
                var store = scope.ServiceProvider.GetService<IBlogStore>();
                var request = arg.Message.Body.ToObjectFromJson<BlogRequest>();
                result = await store.DeleteBlogAsync(request.Blog);
            }

            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(result))
            {
                SessionId = arg.Message.SessionId
            };
            await sender.SendMessageAsync(response);

        }
        private async Task UpdateBlogReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            BlogResult result;
            using (var scope = _factory.CreateScope())
            {
                var store = scope.ServiceProvider.GetService<IBlogStore>();
                var request = arg.Message.Body.ToObjectFromJson<BlogRequest>();
                result = await store.UpdateBlogAsync(request.Blog);
            }

            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(result))
            {
                SessionId = arg.Message.SessionId
            };
            await sender.SendMessageAsync(response);
        }
    }
}
