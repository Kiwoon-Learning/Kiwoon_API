namespace SharedModels.Domain.Blog
{
    public class BlogRequest : BusRequest
    {
        public BlogRequest()
        {
        }

        public BlogRequest(Blog blog)
        {
            Blog = blog;
        }
        public Blog Blog { get; set; }
    }
}
