using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using var rsa=RSA.Create(2048);
var keys=new SecurityKey[]{new RsaSecurityKey(rsa){KeyId="rsa-enc"},new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(64)){KeyId="aes-enc"}};
foreach(var alg in new[]{"RSA-OAEP","dir"})
{
 var key=alg.StartsWith("RSA")?keys[0]:keys[1];
 try{var token=new JsonWebTokenHandler().EncryptToken("eyJhbGciOiJub25lIn0.e30.",new EncryptingCredentials(key,alg,"A256CBC-HS512"),new Dictionary<string,object>{{"typ","at+jwt"},{"cty","JWT"}});Console.WriteLine(alg+" supported segments="+token.Split('.').Length+" header="+new JsonWebToken(token).EncodedHeader);}
 catch(Exception e){Console.WriteLine(alg+" FAILED "+e.GetType().Name+" "+e.Message.Split('\n')[0]+" INNER="+e.InnerException?.Message);}
}
