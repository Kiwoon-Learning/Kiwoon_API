using System;
using System.Linq;
using System.Threading.Tasks;
using Kiwoon.Blogs.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SharedModels.Domain.Blog;

namespace Kiwoon.Blogs.Services
{
    public class BlogStore : IBlogStore
    {
        private readonly IServiceScopeFactory _factory;
        private readonly ILogger<BlogStore> _logger;

        public BlogStore(IServiceScopeFactory factory, ILogger<BlogStore> logger)
        {
            _factory = factory;
            _logger = logger;
        }
        
        public async Task<BlogResult> CreateBlogAsync(Blog blog)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<BlogDbContext>();
            try
            {
                await context.Blogs.AddAsync(blog);
                await context.SaveChangesAsync();
            }
            catch(Exception e)
            {
                _logger.LogError(e, "Error in blog store", blog);
                return new BlogResult(false, blog);
            }

            return new BlogResult(true, blog);
        }

        public async Task<BlogResult> UpdateBlogAsync(Blog blog)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<BlogDbContext>();
            try
            {
                context.Blogs.Update(blog);
                await context.SaveChangesAsync();
            }
            catch(Exception e)
            {
                _logger.LogError(e, "Error in blog store", blog);
                return new BlogResult(false, blog);
            }

            return new BlogResult(true, blog);
        }

        public async Task<BlogResult> DeleteBlogAsync(Blog blog)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<BlogDbContext>();
            try
            {
                context.Blogs.Remove(blog);
                await context.SaveChangesAsync();
            }
            catch(Exception e)
            {
                _logger.LogError(e, "Error in blog store", blog);
                return new BlogResult(false, blog);
            }

            return new BlogResult(true, blog);
        }

        public async Task<BlogResult> GetBlogByIdAsync(string id)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<BlogDbContext>();
            try
            {
                return new BlogResult(true, await context.Blogs.FindAsync(id));
            }
            catch(Exception e)
            {
                _logger.LogError(e, "Error in blog store", id);
                return new BlogResult(false);
            }
        }

        public async Task<BlogResult> GetAllBlogsAsync()
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<BlogDbContext>();
            try
            {
                return new BlogResult(true, await context.Blogs.ToArrayAsync());
            }
            catch(Exception e)
            {
                _logger.LogError(e, "Error in blog store");
                return new BlogResult(false);
            }
        }

        public async Task<BlogResult> SearchBlogsAsync(string searchQuery)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<BlogDbContext>();
            try
            {
                return new BlogResult(true, await context.Blogs.Where(x => x.Description.Contains(searchQuery) ||
                                                                           x.Name.Contains(searchQuery)
                                                                           || x.Tags.Contains(searchQuery))
                    .ToArrayAsync() ?? new[] {await context.Blogs.FindAsync(searchQuery)});
            }
            catch(Exception e)
            {
                _logger.LogError(e, "Error in blog store", searchQuery);
                return new BlogResult(false);
            }
        }
        
    }
}