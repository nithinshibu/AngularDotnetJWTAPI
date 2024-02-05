using AngularDotnetJWTAPI.Models;
using MailKit.Net.Smtp;
using MimeKit;

namespace AngularDotnetJWTAPI.UtilityService
{
	public class EmailService : IEmailService
	{
		private readonly IConfiguration _config;	
        public EmailService(IConfiguration config)
        {
			_config = config;   
        }
        public void SendEmail(EmailModel email)
		{
			var emailContent = new MimeMessage();
			var fromEmail = _config["EmailSettings:From"];
			emailContent.From.Add(new MailboxAddress("AngularDotnetProject",fromEmail));
			emailContent.To.Add(new MailboxAddress(email.ToEmail, email.ToEmail));
			emailContent.Subject=email.Subject;
			emailContent.Body = new TextPart(MimeKit.Text.TextFormat.Html)
			{
				Text = string.Format(email.Content)
			};

			using(var client = new SmtpClient())
			{
				try
				{
					client.Connect(_config["EmailSettings:SmtpServer"],465,true);
					client.Authenticate(_config["EmailSettings:From"], _config["EmailSettings:Password"]);
					client.Send(emailContent);


				}
				catch (Exception)
				{

					throw;
				}
				finally
				{
					client.Disconnect(true);
					client.Dispose();
				}
			}

		}
	}
}
