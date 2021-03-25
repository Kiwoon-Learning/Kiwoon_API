using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Messaging.ServiceBus;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SharedModels.Domain.Blog;

namespace Kiwoon.Blogs.Workers
{
    public class FindBlogReceiver : BackgroundService
    {
        private readonly IServiceScopeFactory _factory;
        private readonly ServiceBusClient _client;

        public FindBlogReceiver(IServiceScopeFactory factory, ServiceBusClient client)
        {
            _factory = factory;
            _client = client;
        }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await using var findBlogByIdReceiver = _client.CreateSessionProcessor("FindBlogById");
            await using var getAllBlogsReceiver = _client.CreateSessionProcessor("GetAllBlogs");
            await using var searchBlogsReceiver = _client.CreateSessionProcessor("SearchBlogs");

            findBlogByIdReceiver.ProcessMessageAsync += FindBlogByIdReceiveMessageAsync;
            findBlogByIdReceiver.ProcessErrorAsync += args => throw args.Exception;
            getAllBlogsReceiver.ProcessMessageAsync += GetAllBlogsReceiveMessageAsync;
            getAllBlogsReceiver.ProcessErrorAsync += args => throw args.Exception;
            searchBlogsReceiver.ProcessMessageAsync += SearchBlogsReceiveMessageAsync;
            searchBlogsReceiver.ProcessErrorAsync += args => throw args.Exception;

            await findBlogByIdReceiver.StartProcessingAsync(stoppingToken);
            await getAllBlogsReceiver.StartProcessingAsync(stoppingToken);
            await searchBlogsReceiver.StartProcessingAsync(stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
                await Task.Delay(1000, stoppingToken);
        }

        private async Task FindBlogByIdReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            BlogResult result;
            using (var scope = _factory.CreateScope())
            {
                var store = scope.ServiceProvider.GetService<IBlogStore>();
                var request = arg.Message.Body.ToObjectFromJson<BlogRequest>();
                result = await store.GetBlogByIdAsync(request.Blog.Id);
            }

            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(result))
            {
                SessionId = arg.SessionId
            };
            await sender.SendMessageAsync(response);
        }
        private async Task GetAllBlogsReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            BlogResult result;
            using (var scope = _factory.CreateScope())
            {
                var store = scope.ServiceProvider.GetService<IBlogStore>();
                result = await store.GetAllBlogsAsync();
            }

            await using var sender = _client.CreateSender("Response");
            var response = new ServiceBusMessage(JsonSerializer.SerializeToUtf8Bytes(result))
            {
                SessionId = arg.SessionId
            };
            await sender.SendMessageAsync(response);

        }
        private async Task SearchBlogsReceiveMessageAsync(ProcessSessionMessageEventArgs arg)
        {
            BlogResult result;
            using (var scope = _factory.CreateScope())
            {
                var store = scope.ServiceProvider.GetService<IBlogStore>();
                var request = arg.Message.Body.ToObjectFromJson<BlogRequest>();
                result = await store.SearchBlogsAsync(request.Blog.Description);
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
