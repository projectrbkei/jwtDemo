using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace jwtDemo
{
    [Route("api/[action]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        [HttpPost]
        [AllowAnonymous]

        public IActionResult CreateTokan([FromForm] AppUserAPIModel login)
        {
            IActionResult responce = Unauthorized();
            if (!string.IsNullOrEmpty(login.Password) && !string.IsNullOrEmpty(login.UserName) && !string.IsNullOrEmpty(login.DeviceId))
            {

                if (login.UserName == "Sohan" && login.Password == "MyPass" && login.DeviceId == "MyDevice")
                {
                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("r#@rb#@rbk#@rbke#@rbkei#@"));
                    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                    login.UserClaims.Add(new Claim("Role", "Employee"));
                    login.UserClaims.Add(new Claim("Name", login.UserName));
                    login.UserClaims.Add(new Claim("Id", "5"));
                    var tokan = new JwtSecurityToken("https://localhost:44395/", "*", login.UserClaims, expires: DateTime.Now.AddDays(10), signingCredentials: creds);
                    var tokanstring = new JwtSecurityTokenHandler().WriteToken(tokan);
                    responce = Ok(new { tokan = tokanstring });
                }
            }
            return responce;
        }

        [HttpGet]
        [Authorize]
        public IActionResult GetAPIResult([FromQuery] AppUserAPIModel querydata)
        {
            IActionResult responce = Unauthorized();
            if(!string.IsNullOrEmpty(querydata.Token))
            {
                var tokanstring = new JwtSecurityTokenHandler().ReadToken(querydata.Token);
                responce = Ok(new { tokan = tokanstring });
            }
            return responce;
        }

    }

    public class AppUserAPIModel
    {
        public AppUserAPIModel()
        {
            UserClaims = new List<Claim>();

        }
        public List<Claim> UserClaims { get; set; }
        public int MyProperty { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Email { get; set; }
        public string DeviceId { get; set; }
        public string DeviceHostName { get; set; }
        public string DeviceMac { get; set; }
        public string FullName { get; set; }
        public string Token { get; set; }
    }
}
