using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenservice;
        public AccountController(DataContext context, ITokenService tokenservice)
        {
            _tokenservice = tokenservice;
            _context = context;
        }
        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto){

            if(await UserExist(registerDto.username)) return BadRequest("this username is taken");
            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                Username= registerDto.username.ToLower(),
                PasswordHash=hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.password)),
                PasswordSalt = hmac.Key,

            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return new UserDto{
                username=user.Username,
                Token=_tokenservice.CreateToken(user)
            };
        
        }
        [HttpPost("Login")]
        public async Task<ActionResult<UserDto>> login(LoginDto loginDto )
        {
            var user= await _context.Users.
                  SingleOrDefaultAsync(x =>x.Username == loginDto.username );
                  if(user==null) return Unauthorized("Invalid username");
                  using var hmac = new HMACSHA512(user.PasswordSalt);
                  var computedhas = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.password));
                  for(int i = 0 ; i<computedhas.Length;i++)
                  {
                      if(computedhas[i] != user.PasswordHash[i]) return Unauthorized("invalid password");
                  }
                      return new UserDto{
                username=user.Username,
                Token=_tokenservice.CreateToken(user)
            };
        }
        private Task<bool>UserExist(string username)
        {
            return _context.Users.AnyAsync(x => x.Username == username.ToLower());
        }
    }
}