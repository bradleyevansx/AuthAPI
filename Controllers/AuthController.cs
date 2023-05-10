using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Authentication.Models;
using Authentication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Authentication.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private static User _user = new User();
    private readonly IConfiguration _configuration;
    private readonly IUserService _userService;

    public AuthController(IConfiguration configuration, IUserService userService)
    {
        _configuration = configuration;
        _userService = userService;
    }

    [HttpGet, Authorize]
    public ActionResult<string> GetMyName()
    {
        return Ok(_userService.GetMyName());
    }

        [HttpPost("register")]
    public ActionResult<User> Register(UserDTO request)
    {

        _user.Username = request.Username;
        _user.Password = request.Password;

        return Ok(_user);
    }
    [HttpPost("login")]
    public ActionResult<string> Login(UserDTO request)
    {
        if (_user.Username != request.Username)
        {
            return BadRequest("User Not Found.");
        }

        if (_user.Password != request.Password)
        {
            return BadRequest("Wrong Password");
        }

        var token = CreateToken(_user);

        var refreshToken = GenerateRefreshToken();
        SetRefreshToken(refreshToken);

        return Ok(token);
    }

    [HttpPost("refresh-token")]
    public async Task<ActionResult<string>> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];

        if (!_user.RefreshToken.Equals(refreshToken))
        {
            return Unauthorized("Invalid Refresh Token.");
        }

        if (_user.TokenExpired < DateTime.Now)
        {
            return Unauthorized("Token Expired");
        }

        string token = CreateToken(_user);
        var newRefreshToken = GenerateRefreshToken();
        SetRefreshToken(newRefreshToken);

        return Ok(token);
    }

    private void SetRefreshToken(RefreshToken newRefreshToken)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = newRefreshToken.Expired
        };
        Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

        _user.RefreshToken = newRefreshToken.Token;
        _user.TokenCreated = newRefreshToken.Created;
        _user.TokenExpired = newRefreshToken.Expired;
    }

    private RefreshToken GenerateRefreshToken()
    {
        var refreshToken = new RefreshToken()
        {
            Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            Expired = DateTime.Now.AddHours(1)
        };
        return refreshToken;
    }

    private string CreateToken(User user)
    {
        List<Claim> claims = new()
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, "Admin"),
            new Claim(ClaimTypes.Role, "User"),
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value!));

        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

        var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds
            );

        var jwt = new JwtSecurityTokenHandler().WriteToken(token);

        return jwt;
    }
}