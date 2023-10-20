using cu.ApiBasics.Lesvoorbeeld.Avond.Api.DTOs.Account;
using cu.ApiBAsics.Lesvoorbeeld.Avond.Core.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace cu.ApiBasics.Lesvoorbeeld.Avond.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;


        public AccountController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, IConfiguration configuration)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _configuration = configuration;
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginRequestDto loginRequestDto)
        {
            var result = await _signInManager.PasswordSignInAsync(loginRequestDto.Username, loginRequestDto.Password,false,false);
            if(!result.Succeeded)
            {
                return Unauthorized();
            }
            var user = await _userManager.FindByNameAsync(loginRequestDto.Username);
            var claims = await _userManager.GetClaimsAsync(user);
            var expirationDays = _configuration.GetValue<int>("JWTConfiguration:TokenExpiration");
            var signinKey = Encoding.UTF8.GetBytes(_configuration.GetValue<string>("JWTConfiguration:SigninKey"));
            var token = new JwtSecurityToken(
                issuer: _configuration.GetValue<string>("JWTConfiguration:Issuer"),
                audience: _configuration.GetValue<string>("JWTConfiguration:Audience"),
                claims: claims,
                expires: DateTime.Now.AddDays(expirationDays),
                notBefore: DateTime.Now,
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(signinKey),SecurityAlgorithms.HmacSha256)
                );
            var serializedToken = new JwtSecurityTokenHandler().WriteToken(token);
            return Ok(serializedToken);
        }
    }
}
