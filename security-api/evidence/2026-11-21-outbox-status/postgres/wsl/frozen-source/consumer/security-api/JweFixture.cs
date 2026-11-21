using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Cehpalon.Engine.Identity.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SecurityApi;

/// <summary>Ephemeral nested signed-token fixture. Keys, plaintext and encrypted credentials never go to disk/logs.</summary>
public sealed class JweFixture:IDisposable
{
    private readonly RSA? rsa;
    private readonly byte[]? secret;
    public JweFixture(string keyManagementAlgorithm,string contentEncryptionAlgorithm="A256CBC-HS512")
    {
        KeyManagementAlgorithm=keyManagementAlgorithm;ContentEncryptionAlgorithm=contentEncryptionAlgorithm;
        if(keyManagementAlgorithm.StartsWith("RSA-",StringComparison.Ordinal))rsa=RSA.Create(2048);
        else if(keyManagementAlgorithm=="dir")secret=RandomNumberGenerator.GetBytes(contentEncryptionAlgorithm=="A256CBC-HS512"?64:32);
        else throw new ArgumentException("Use one of the declared local fixture encryption profiles.",nameof(keyManagementAlgorithm));
    }
    public string KeyManagementAlgorithm{get;}
    public string ContentEncryptionAlgorithm{get;}
    public string KeyId=>"fixture-decrypt-"+KeyManagementAlgorithm;
    public SecurityKey DecryptionKey=>rsa is not null?new RsaSecurityKey(rsa){KeyId=KeyId}:new SymmetricSecurityKey(secret!){KeyId=KeyId};
    private SecurityKey EncryptionKey=>rsa is not null?new RsaSecurityKey(rsa.ExportParameters(false)){KeyId=KeyId}:new SymmetricSecurityKey(secret!){KeyId=KeyId};
    public JwtProfileSettings Settings=>new(){Scheme="Bearer",Issuer=JwtFixture.Issuer,Audience=JwtFixture.Audience,Algorithm="RS256",TokenType="at+jwt",KeySource=JwtKeySource.PublicJwks,
        TokenProtection=JwtTokenProtection.EncryptedSigned,KeyManagementAlgorithm=KeyManagementAlgorithm,ContentEncryptionAlgorithm=ContentEncryptionAlgorithm};
    public string Token(JwtFixture signing,string subject="alice",string? inner=null)
        =>Encrypt(inner??signing.Token(subject));
    public string Encrypt(string inner)
        =>new JsonWebTokenHandler().EncryptToken(inner,new(EncryptionKey,KeyManagementAlgorithm,ContentEncryptionAlgorithm),new Dictionary<string,object>{{"typ","at+jwt"},{"cty","JWT"}});
    public static string UnsignedInner(string subject="alice")
    {
        var now=DateTime.UtcNow;var inner=new JwtSecurityToken(JwtFixture.Issuer,JwtFixture.Audience,[new Claim("sub",subject)],now.AddMinutes(-1),now.AddMinutes(5));
        inner.Header["typ"]="at+jwt";return new JwtSecurityTokenHandler().WriteToken(inner);
    }
    // Negative-fixture byte/header mutations only. Production parsing/decryption stays in the established handler.
    public static string Header(string token,string key,string? value)
    {
        var parts=token.Split('.');var header=JsonNode.Parse(Base64UrlEncoder.DecodeBytes(parts[0]))!;
        if(value is null)header.AsObject().Remove(key);else header[key]=value;
        parts[0]=Base64UrlEncoder.Encode(System.Text.Encoding.UTF8.GetBytes(header.ToJsonString()));return string.Join('.',parts);
    }
    public static string Tamper(string token,int part)
    {
        var parts=token.Split('.');var data=Base64UrlEncoder.DecodeBytes(parts[part]);data[0]^=1;parts[part]=Base64UrlEncoder.Encode(data);return string.Join('.',parts);
    }
    public void Dispose(){rsa?.Dispose();if(secret is not null)CryptographicOperations.ZeroMemory(secret);}
}
