namespace Kiwoon.Domain.Identity.User
{
    public class EmailRequest : BusRequest
    {
        public EmailRequest()
        {
            
        }

        public EmailRequest(string email, string subject, string htmlMessage)
        {
            Email = email;
            Subject = subject;
            HtmlMessage = htmlMessage;
        }

        public string Email { get; set; }
        public string Subject { get; set; }
        public string HtmlMessage { get; set; }
    }
}
