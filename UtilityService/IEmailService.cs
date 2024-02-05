using AngularDotnetJWTAPI.Models;

namespace AngularDotnetJWTAPI.UtilityService
{
	public interface IEmailService
	{
		void SendEmail(EmailModel email);
	}
}
