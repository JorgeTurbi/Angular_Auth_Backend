using AngularAuthAPI.Context;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

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
                .FirstOrDefaultAsync(x=>x.Username==userObj.Username && x.Password==userObj.Password);
            if (user == null) return NotFound(new {Message="User Not Found!" });

            return Ok(new
            {
                Message="Login Success!"
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if(userObj == null) return BadRequest();
            await _context.Users.AddAsync(userObj);
            await _context.SaveChangesAsync();
            return Ok(new {Message="User Registered!"});
        }
    }
}
