using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using var rsa=RSA.Create(2048);var key=new RsaSecurityKey(rsa){KeyId="fixture"};
var jwt=new JwtSecurityToken("urn:test","test",null,DateTime.UtcNow.AddMinutes(-1),DateTime.UtcNow.AddMinutes(1),new SigningCredentials(key,"RS256"));
var token=new JwtSecurityTokenHandler().WriteToken(jwt);var handler=new CountingHandler();
var result=await handler.ValidateTokenAsync(token,new TokenValidationParameters{IssuerSigningKey=key,ValidateIssuer=false,ValidateAudience=false,ValidateLifetime=true});
Console.WriteLine("valid="+result.IsValid+" SecurityTokenOverrideCalls="+handler.Calls);
sealed class CountingHandler:JsonWebTokenHandler
{
 public int Calls;
 public override Task<TokenValidationResult> ValidateTokenAsync(SecurityToken token,TokenValidationParameters parameters)
 {Calls++;return base.ValidateTokenAsync(token,parameters);}
}
