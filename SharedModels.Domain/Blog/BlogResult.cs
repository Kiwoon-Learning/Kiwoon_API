using System;

namespace SharedModels.Domain.Blog
{
    public class BlogResult
    {
        public BlogResult(bool succeeded, params Blog[] blogs)
        {
            Succeeded = succeeded;
            Blogs = blogs ?? Array.Empty<Blog>();
        }
        public bool Succeeded { get; set; }
        public Blog[] Blogs { get; set; }
    }
}
