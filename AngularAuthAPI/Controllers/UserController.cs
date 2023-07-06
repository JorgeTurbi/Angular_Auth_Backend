using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using AngularAuthAPI.Models.Dto;
using AngularAuthAPI.UtilityService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _config;
        private readonly IEmailService _EmailService;
        public UserController(AppDbContext appDbContext, IConfiguration config, IEmailService emailService)
        {
            _context = appDbContext;
            _config = config;
            _EmailService = emailService;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
          
            if (userObj == null) return BadRequest();
            var user = await _context.Users
                .FirstOrDefaultAsync(x => x.Username == userObj.Username);
            if (user == null) return NotFound(new { Message = "User Not Found!" });

            if(!PasswordHasher.VerifyPassword(userObj.Password,user.Password))
                return BadRequest("Password is Incorrect");

          
            user.Token = CreateJwt(user);
            var newAccessToken = user.Token;
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newAccessToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(5);
            await _context.SaveChangesAsync();

            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }
        [Authorize]
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null) return BadRequest();

            //check username
            if (await CheckUserNameExistAsync(userObj.Username))
                return BadRequest(new { Message = "Username Already Exist!" });
            //Check Email
            if (await CheckEmailExistAsync(userObj.Email))
                return BadRequest(new { Message = "Email Already Exist!" });

            //Check password Strength
            var pass = CheckPasswordStrength(userObj.Password);

            if (!string.IsNullOrEmpty(pass))            
                return BadRequest(new {Message=pass.ToString() });
            
            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            //userObj.Role = "User";
            userObj.Token = "";
            await _context.Users.AddAsync(userObj);
            await _context.SaveChangesAsync();
            return Ok(new { Message = "User Added!" });
        }

        private async Task<bool> CheckUserNameExistAsync(string username)
        => await _context.Users.AnyAsync(x => x.Username == username);

        private async Task<bool> CheckEmailExistAsync(string email)
      => await _context.Users.AnyAsync(x => x.Email == email);

        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if (password .Length< 8) sb.Append("Minimum password length show be 8"+Environment.NewLine);

            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be  Alphanumeric"+Environment.NewLine);
            if (!Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+\\[,\\],{,},?:,;,|,',\\,.,/,~,`,-,=]"))
                sb.Append("Password should contain special chars"+Environment.NewLine);
            return sb.ToString();
        }

       private string CreateJwt(User user)
        {
           
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysecret....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                //user.Role
                new Claim(ClaimTypes.Role,user.IdRoles.ToString()),
                new Claim(ClaimTypes.Name,$"{user.Username}")

            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha256);
           
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.UtcNow.AddMinutes(60),
               // NotBefore = DateTime.UtcNow,
                SigningCredentials = credentials,
            };
            var token=jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }

        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);

            var tokenInUser = _context.Users.Any(a=>a.RefreshToken==refreshToken);

            if (tokenInUser)
            {
                return CreateRefreshToken();
                
            }
            return refreshToken;
        }
        
        private ClaimsPrincipal GetPrincipleFromExpiredToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("veryverysecret....");
            var tokenValidationparameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false,
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationparameters, out securityToken);
            var jwtSecurityToken=securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null|| !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("This is Invalid Token");
            }

            return principal;


        }

        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUser()
        {
            return Ok(await _context.Users.Include(u => u.Roles).ToListAsync());
            //return Ok(await _context.Users.Include(u => u.Roles).ToListAsync());
        }
       
        [Authorize(Roles="1")]
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDto tokenApiDto)
        {
            if (tokenApiDto is null)
                return BadRequest("Invalid Client Request");
            string accessToken =tokenApiDto.AccessToken;
            string refreshToken=tokenApiDto.RefreshToken;
            var principal = GetPrincipleFromExpiredToken(accessToken);
            var username = principal.Identity.Name;
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                return BadRequest("Invalid Request");
            
            var newAcccessToken = CreateJwt(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _context.SaveChangesAsync();
            
            
            return Ok(new TokenApiDto{ 
                AccessToken= newAcccessToken,
                RefreshToken=newRefreshToken               
            
            });
                                
            
        }
        
        [HttpPost("send-reset-email/{email}")]
        public async Task<IActionResult> SendEmail(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(a => a.Email == email);
            if (user is null)
            {
                return NotFound(new{ 
                StatusCode=404,
                Message="email Doesn't Exist"
                });
            }
                var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var emailToken = Convert.ToBase64String(tokenBytes);
            user.ResetPasswordToken=emailToken;
            user.ResetPasswordExpiry=DateTime.Now.AddMinutes(15);
            string from = _config["EmailSettings:From"];
            var emailModel = new EmailModel(email,"Reset Password!!",EmailBody.EmailStringBody(email, user.ResetPasswordToken));
            _EmailService.SendEmail(emailModel);
            _context.Entry(user).State = EntityState.Modified;
            await _context.SaveChangesAsync();
            return Ok(new
            {
                StatusCode=200,
                Message="Email Sent!"
            });
        }
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword( ResetPasswordDto resetPasswordDto)
        {
            var newToken = resetPasswordDto.EmailToken.Replace(" ","+");
            var user = await _context.Users.AsNoTracking().FirstOrDefaultAsync(a=>a.Email==resetPasswordDto.Email);

            if (user is null)
            {
                return NotFound(new
                {
                    StatusCode = 404,
                    Message = "User Doesn't Exist"
                });
            }
            var tokenCode = user.ResetPasswordToken;
            DateTime emailTokenExpiry = user.ResetPasswordExpiry;
            if (tokenCode !=resetPasswordDto.EmailToken || emailTokenExpiry<DateTime.Now)
            {
                return BadRequest(new
                {
                    StatusCode=400,
                    Message="Invalid Reset Link"
                });
            }
            user.Password = PasswordHasher.HashPassword(resetPasswordDto.NewPassword);
            _context.Entry(user).State = EntityState.Modified;
            await _context.SaveChangesAsync();

            return Ok(new
            {
                StatusCode=200,
                Message="Password Reset Successfully"
            });

        }

        [Authorize]
        [HttpPost("NewRole")]     
        public  async Task<IActionResult> NewRole(Roles roles)
        {           
            try
            {
                   
                await _context.Roles.AddAsync(roles);
                await _context.SaveChangesAsync();
             
            }
            catch (Exception ex)
            {

                return BadRequest(ex.Message.ToString());
             
            }
            return Ok(new { Message = "Role Added!" });
        }
        [Authorize]
        [HttpGet("Roles")]
       public async Task<IActionResult> GetAllRoles()
        {
            return Ok(await _context.Roles.Include(a=>a.users).ToListAsync());
        }

        private async Task<Roles> GetRol(int IdRol)
        {
            Roles role = await _context.Roles.FirstOrDefaultAsync(a => a.Id == IdRol);
            if (role == null)
                return new Roles();
            return role;
        }

    
     
        

    }



}
