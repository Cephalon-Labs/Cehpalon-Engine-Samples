using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Cehpalon.Engine.Identity.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace SecurityApi;

/// <summary>Ephemeral local signature fixtures only; no key/token serialization to disk.</summary>
public sealed class JwtProfileFixture:IDisposable
{
    private readonly RSA? rsa;
    private readonly ECDsa? ec;
    private readonly ECDsa? publicEc;
    private readonly byte[]? secret;
    public JwtProfileFixture(string algorithm)
    {
        Algorithm=algorithm;
        if(algorithm is "RS256" or "PS256")rsa=RSA.Create(2048);
        else if(algorithm=="ES256"){ec=ECDsa.Create(ECCurve.NamedCurves.nistP256);publicEc=ECDsa.Create(ec.ExportParameters(false));}
        else if(algorithm=="HS256")secret=RandomNumberGenerator.GetBytes(32);
        else throw new ArgumentException("Fixture supports declared representatives only.",nameof(algorithm));
    }
    public string Algorithm{get;}
    public JwtProfileSettings Settings=>new(){Scheme="Bearer",Issuer=JwtFixture.Issuer,Audience=JwtFixture.Audience,Algorithm=Algorithm,TokenType="at+jwt",
        KeySource=Algorithm=="RS256"?JwtKeySource.PublicJwks:JwtKeySource.ProvidedKeys};
    private string KeyId=>"fixture-"+Algorithm;
    public SecurityKey VerificationKey=>rsa is not null?new RsaSecurityKey(rsa.ExportParameters(false)){KeyId=KeyId}:
        publicEc is not null?new ECDsaSecurityKey(publicEc){KeyId=KeyId}:new SymmetricSecurityKey(secret!){KeyId=KeyId};
    private SecurityKey SigningKey=>rsa is not null?new RsaSecurityKey(rsa){KeyId=KeyId}:
        ec is not null?new ECDsaSecurityKey(ec){KeyId=KeyId}:new SymmetricSecurityKey(secret!){KeyId=KeyId};
    public string PublicJwks()
    {
        if(rsa is null)throw new InvalidOperationException("Fixture public JWKS uses RSA only.");
        var key=rsa.ExportParameters(false);
        return System.Text.Json.JsonSerializer.Serialize(new{keys=new[]{new{kty="RSA",kid=KeyId,use="sig",alg=Algorithm,n=Base64UrlEncoder.Encode(key.Modulus!),e=Base64UrlEncoder.Encode(key.Exponent!)}}});
    }
    public string Token(string subject="alice",bool unsigned=false,string? kid=null)
    {
        var now=DateTime.UtcNow;
        var token=new JwtSecurityToken(JwtFixture.Issuer,JwtFixture.Audience,[new Claim("sub",subject)],now.AddMinutes(-1),now.AddMinutes(5),unsigned?null:new SigningCredentials(SigningKey,Algorithm));
        token.Header["typ"]="at+jwt";if(kid is not null)token.Header["kid"]=kid;
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    public void Dispose(){rsa?.Dispose();ec?.Dispose();publicEc?.Dispose();if(secret is not null)CryptographicOperations.ZeroMemory(secret);}
}
