namespace SharedModels.Domain.Identity
{
    public class FindByRequest : BusRequest
    {
        public string SearchQuery { get; set; }
    }
}
