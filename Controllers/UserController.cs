using AngularDotnetJWTAPI.Context;
using AngularDotnetJWTAPI.Helpers;
using AngularDotnetJWTAPI.Models;
using AngularDotnetJWTAPI.Models.DTO;
using AngularDotnetJWTAPI.UtilityService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularDotnetJWTAPI.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class UserController : ControllerBase
	{
        private readonly AppDbContext _authContext;
		private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
		public UserController(AppDbContext appDbContext, IConfiguration configuration,IEmailService emailService)
        {
			_configuration = configuration;
			_authContext = appDbContext;
            _emailService = emailService;
        }


		[Authorize]
		[HttpGet]
		public async Task<ActionResult<User>> GetAllUsers()
		{
			return Ok(await _authContext.Users.ToListAsync());
		}


		[HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if(userObj == null)
            {
                return BadRequest();//400 error
            }

            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName);
            if(user == null)
            {
                return NotFound(new { Message = "User Not Found" });
            }

            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {
                return BadRequest(new { Message="Incorrect User credentials" });
            }
            user.Token = CreateJwtToken(user);

            var newAccessToken = user.Token;
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);
            await _authContext.SaveChangesAsync();

			return Ok(new TokenApiDTO
            {
                AccessToken=newAccessToken,
                RefreshToken =newRefreshToken
            });
        }
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if(userObj == null)
            {
                return BadRequest();
            }
            //Check Username
            if(await CheckUserNameExistsAsync(userObj.UserName))
            {
                return BadRequest(new { Message = "UserName Already Exists" });
            }

			//Check Email
			if (await CheckEmailExistsAsync(userObj.Email))
			{
				return BadRequest(new { Message = "Email Already Exists" });
			}

            //Check Password Strength
            string pass = CheckPasswordStrength(userObj.Password);
            if(!string.IsNullOrEmpty(pass))
            {
                return BadRequest(new { Message = pass });
            }


			userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new { Message = "User Registered!" });
        }

        private async  Task<bool> CheckUserNameExistsAsync(string username)
        {
            return await _authContext.Users.AnyAsync(x => x.UserName == username);
        }

        private Task<bool> CheckEmailExistsAsync(string email) => _authContext.Users.AnyAsync(x=>x.Email==email);

        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if(password.Length < 8)
                sb.Append("Minmum Password Length should be 8."+Environment.NewLine);
			if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
				sb.Append("Password should be AlphaNumeric" + Environment.NewLine);
			if (!Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]"))
				sb.Append("Password should contain special charcter" + Environment.NewLine);
			return sb.ToString();

		}

        private string CreateJwtToken(User user)
        {
            //Token is made of Header,Payload and Signature.
            var jwtTokenHandler = new JwtSecurityTokenHandler();

			var key = Encoding.ASCII.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value);
            //JWT Payload will have 2 data
            //Role and Name
            
			var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role,user.Role),
                //new Claim(ClaimTypes.Name,$"{user.FirstName} {user.LastName}")
                new Claim("username",$"{user.UserName}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            //Create Token Descriptor
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject=identity,
                Expires=DateTime.Now.AddMinutes(5),
                SigningCredentials = credentials
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);

        }

        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);

            var tokenInUser = _authContext.Users.Any(a => a.RefreshToken == refreshToken);
            if (tokenInUser)
            {
                return CreateRefreshToken();
            }
            return refreshToken;
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string expiredToken)
        {
			var key = Encoding.ASCII.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value);
			var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
				ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false
			};

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(expiredToken,tokenValidationParameters,out securityToken);

            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("This is invalid token");
            }
            return principal;


        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDTO tokenApiDTO)
        {
            if (tokenApiDTO is null)
            {
                return BadRequest("Invalid Client Request");
            }

            string accessToken = tokenApiDTO.AccessToken;
            string refreshToken = tokenApiDTO.RefreshToken; 
            var principal = GetPrincipalFromExpiredToken(accessToken);
            var username = principal?.FindFirst("username").Value;
            var user = await _authContext.Users.FirstOrDefaultAsync(u => u.UserName == username);

            if(user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid Request");
            }

            var newAccessToken = CreateJwtToken(user);
            var newRefreshToken = CreateRefreshToken();
            user.Token = newAccessToken;
            user.RefreshToken=newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);
            await _authContext.SaveChangesAsync();

            return Ok(new TokenApiDTO()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });


        }

        [HttpPost("send-reset-email/{email}")]
        public async Task<IActionResult> SendEmail(string email)
        {
            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Email == email);
            if(user is null)
            {
                return NotFound(new {StatusCode=404,Message="Email doesn't exist."});
            }
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var emailToken = Convert.ToBase64String(tokenBytes);
            user.ResetPasswordToken = emailToken;
            user.ResetPasswordTokenExpiryTime = DateTime.Now.AddMinutes(15);
            string fromEmail = _configuration["EmailSettings:From"];
            var emailModel = new EmailModel(email, "Reset Password", EmailBody.EmailStringBody(email, emailToken));
            _emailService.SendEmail(emailModel);
            _authContext.Entry(user).State = EntityState.Modified;
            await _authContext.SaveChangesAsync();
            return Ok( new { StatusCode = 200,Message="Email Sent!"});
        }

        [HttpPost("reset-password")]

        public async Task<IActionResult> ResetPassword(ResetPasswordDTO resetPasswordDTO)
        {
            var newToken = resetPasswordDTO.EmailToken.Replace(" ", "+");
            var user = await _authContext.Users.AsNoTracking().FirstOrDefaultAsync(a => a.Email == resetPasswordDTO.Email);
			if (user is null)
			{
				return NotFound(new { StatusCode = 404, Message = "User doesn't exist." });
			}

            var tokenCode = user.ResetPasswordToken;
            DateTime emailTokenExpiry = user.ResetPasswordTokenExpiryTime;
            if(tokenCode != resetPasswordDTO.EmailToken || emailTokenExpiry <DateTime.Now)
            {
                return BadRequest(new {StatusCode=400,Message="Invalid Reset Link"});
            }


            user.Password = PasswordHasher.HashPassword(resetPasswordDTO.NewPassword);

            _authContext.Entry(user).State= EntityState.Modified;
            await _authContext.SaveChangesAsync();
            return Ok( new {StatusCode = 200,Message="Password Reset Successfully"});
		}



        //private string CreateRefreshToken()
        //{
        //	const int refreshTokenLength = 64;

        //	using (var rng = RandomNumberGenerator.Create())
        //	{
        //		byte[] tokenBytes = new byte[refreshTokenLength];
        //		rng.GetBytes(tokenBytes);

        //		string refreshToken = Convert.ToBase64String(tokenBytes);

        //		// Check for token uniqueness without recursion
        //		while (_authContext.Users.Any(a => a.RefreshToken == refreshToken))
        //		{
        //			// Regenerate a new token if a collision is found
        //			rng.GetBytes(tokenBytes);
        //			refreshToken = Convert.ToBase64String(tokenBytes);
        //		}

        //		return refreshToken;
        //	}
        //}



    }
}
