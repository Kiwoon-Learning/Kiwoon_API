using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace Kiwoon.Gateway.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration;

        public EmailSender(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var msg = new SendGridMessage {
                Subject = subject,
                From = new EmailAddress(_configuration["EmailSender"]),
                HtmlContent = htmlMessage,
                PlainTextContent = htmlMessage
            };
            msg.AddTo(new EmailAddress(email));
            var client = new SendGridClient(_configuration["EmailKey"]);
            await client.SendEmailAsync(msg);
        }
    }
}
