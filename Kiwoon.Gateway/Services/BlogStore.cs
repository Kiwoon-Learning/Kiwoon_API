using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Messaging.ServiceBus;
using SharedModels.Domain;
using SharedModels.Domain.Blog;

namespace Kiwoon.Gateway.Services
{
    public class BlogStore : IBlogStore
    {
        private readonly ServiceBusClient _client;

        public BlogStore(ServiceBusClient client)
        {
            _client = client;
        }
        private async Task<T> SendSessionRequestResponseAsync<T>(string queueName, BusRequest request, Guid guidId, CancellationToken cancellationToken = default)
        {
            var id = guidId.ToString();
            await using var sender = _client.CreateSender(queueName);
            var input = JsonSerializer.SerializeToUtf8Bytes(request, request.GetType());
            await sender.SendMessageAsync(new ServiceBusMessage(input){SessionId = id}, cancellationToken);

            await using var session = await _client.AcceptSessionAsync("Response", id, cancellationToken: cancellationToken);
            var message = await session.ReceiveMessageAsync(cancellationToken: cancellationToken);
            await session.CompleteMessageAsync(message, cancellationToken);
            return message.Body.ToObjectFromJson<T>();
        }

        public async Task<BlogResult> CreateBlogAsync(Blog blog)
        {
            return await SendSessionRequestResponseAsync<BlogResult>("CreateBlog",
                new BlogRequest(blog), Guid.NewGuid());
        }

        public async Task<BlogResult> UpdateBlogAsync(Blog blog)
        {
            return await SendSessionRequestResponseAsync<BlogResult>("UpdateBlog",
                new BlogRequest(blog), Guid.NewGuid());
        }

        public async Task<BlogResult> DeleteBlogAsync(Blog blog)
        {
            return await SendSessionRequestResponseAsync<BlogResult>("DeleteBlog",
                new BlogRequest(blog), Guid.NewGuid());
        }

        public async Task<BlogResult> GetBlogByIdAsync(string id)
        {
            return await SendSessionRequestResponseAsync<BlogResult>("FindBlogById",
                new BlogRequest(new Blog{Id = id}), Guid.NewGuid());
        }

        public async Task<BlogResult> GetAllBlogsAsync()
        {
            return  await SendSessionRequestResponseAsync<BlogResult>("GetAllBlogs",
                new BlogRequest(), Guid.NewGuid());
        }

        public async Task<BlogResult> SearchBlogsAsync(string searchQuery)
        {
            return await SendSessionRequestResponseAsync<BlogResult>("SearchBlogs",
                new BlogRequest(new Blog{Description = searchQuery}), Guid.NewGuid());
        }
    }
}
