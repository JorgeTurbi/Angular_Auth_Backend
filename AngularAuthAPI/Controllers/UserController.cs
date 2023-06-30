﻿using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _context;
        public UserController(AppDbContext appDbContext)
        {
            _context = appDbContext;
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

            return Ok(new
            {
                Message = "Login Success!"
            });
        }

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
            userObj.Role = "User";
            userObj.Token = "";
            await _context.Users.AddAsync(userObj);
            await _context.SaveChangesAsync();
            return Ok(new { Message = "User Registered!" });
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


    }



}
