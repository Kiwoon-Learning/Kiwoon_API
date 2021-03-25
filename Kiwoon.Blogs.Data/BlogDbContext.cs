using System.Collections.Generic;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SharedModels.Domain.Blog;

namespace Kiwoon.Blogs.Data
{
    public class BlogDbContext : DbContext
    {
        public BlogDbContext(DbContextOptions<BlogDbContext> options)
            : base(options)
        {
        }
        public DbSet<Blog> Blogs { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Blog>().Property(b => b.Tags)
                .HasConversion(
                v => JsonSerializer.Serialize(v, null),
                v => JsonSerializer.Deserialize<ICollection<string>>(v, null));
        }
    }
}
