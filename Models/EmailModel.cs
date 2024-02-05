namespace AngularDotnetJWTAPI.Models
{
	public class EmailModel
	{
        public string ToEmail { get; set; }
        public string Subject { get; set; }
        public string Content { get; set; }
        public EmailModel(string toEmail,string subject,string content)
        {
            ToEmail = toEmail;Subject = subject;Content = content;
        }
    }
}
