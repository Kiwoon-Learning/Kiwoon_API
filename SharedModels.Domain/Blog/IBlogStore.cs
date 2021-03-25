using System.Threading.Tasks;

namespace SharedModels.Domain.Blog
{
    public interface IBlogStore
    {
        
        public Task<BlogResult> CreateBlogAsync(Blog blog);
        public Task<BlogResult> UpdateBlogAsync(Blog blog);
        public Task<BlogResult> DeleteBlogAsync(Blog blog);
        public Task<BlogResult> GetBlogByIdAsync(string id);
        public Task<BlogResult> GetAllBlogsAsync();
        public Task<BlogResult> SearchBlogsAsync(string searchQuery);
        
    }
}
