using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SharedModels.Domain.Blog
{
    public class Blog
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string Id { get; set; }
        [Required, StringLength(50)]
        public string Name { get; set; }
        [Required, StringLength(70)]
        public string Description { get; set; }
        public string ImageUrl { get; set; }
        public string DocsId { get; set; }
        
        public ICollection<string> Tags { get; set; }
    }
}
