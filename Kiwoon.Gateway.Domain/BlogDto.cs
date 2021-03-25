using SharedModels.Domain.Blog;

namespace Kiwoon.Gateway.Domain
{
    public class BlogDto
    {
        public static explicit operator BlogDto(Blog blog) =>
            new()
            {
                Id = blog.Id, Description = blog.Description, Name = blog.Name, DocsId = blog.DocsId,
                ImageUrl = blog.ImageUrl
            };
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string ImageUrl { get; set; }
        public string DocsId { get; set; }
    }
}
