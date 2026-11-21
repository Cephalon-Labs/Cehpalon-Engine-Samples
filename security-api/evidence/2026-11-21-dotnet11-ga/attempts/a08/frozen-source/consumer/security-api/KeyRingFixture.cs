using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Cehpalon.Engine.Identity.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SecurityApi;

/// <summary>Trusted in-memory control-plane fixture. Actual keys/tokens never go to files or public endpoints.</summary>
public sealed class KeyRingFixture:IDisposable
{
    private readonly RSA oldSigning=RSA.Create(2048),newSigning=RSA.Create(2048);
    private readonly RSA? oldDecrypt,newDecrypt;
    private readonly byte[]? oldSecret,newSecret;
    public KeyRingFixture(string protection)
    {
        Protection=protection;
        if(protection=="RSA-OAEP"){oldDecrypt=RSA.Create(2048);newDecrypt=RSA.Create(2048);}
        else if(protection=="dir"){oldSecret=RandomNumberGenerator.GetBytes(64);newSecret=RandomNumberGenerator.GetBytes(64);}
        else if(protection!="Signed")throw new ArgumentException("Select a declared ring fixture profile.",nameof(protection));
    }
    public string Protection{get;}
    public FixtureTimeProvider Clock{get;}=new();
    public bool FailCreation;
    public JwtKeyRing? Ring{get;private set;}
    public JwtProfileSettings Settings=>new(){Scheme="Bearer",Issuer=JwtFixture.Issuer,Audience=JwtFixture.Audience,Algorithm="RS256",TokenType="at+jwt",KeySource=JwtKeySource.RotatingKeyRing,
        TokenProtection=Protection=="Signed"?JwtTokenProtection.Signed:JwtTokenProtection.EncryptedSigned,
        KeyManagementAlgorithm=Protection=="Signed"?null:Protection,ContentEncryptionAlgorithm=Protection=="Signed"?null:"A256CBC-HS512"};
    public JwtKeyRing CreateRing(JwtAuthenticationProfile profile)
    {
        if(FailCreation)throw new IOException("Controlled ring provider startup failure.");
        if(Ring is not null)throw new InvalidOperationException("Fixture ring may activate once.");
        Ring=new(profile,TimeSpan.FromMinutes(2),Clock);Publish(true,false,true,false);return Ring;
    }
    public long Publish(bool oldSign,bool newSign,bool oldEncryption,bool newEncryption,long? expectedVersion=null)
    {
        var ring=Ring??throw new InvalidOperationException("Ring has not activated.");
        var signing=new List<SecurityKey>();if(oldSign)signing.Add(Signing(false,false));if(newSign)signing.Add(Signing(true,false));
        List<SecurityKey>? decrypt=null;
        if(Protection!="Signed")
        {
            decrypt=[];if(oldEncryption)decrypt.Add(Decryption(false));if(newEncryption)decrypt.Add(Decryption(true));
        }
        return ring.Publish(expectedVersion??ring.Version,signing,decrypt,Clock.GetUtcNow().AddSeconds(-1),Clock.GetUtcNow().AddMinutes(1));
    }
    public string Token(bool newSign=false,bool newEncryption=false,string subject="alice")
    {
        var now=DateTime.UtcNow;
        var token=new JwtSecurityToken(JwtFixture.Issuer,JwtFixture.Audience,[new Claim("sub",subject)],now.AddMinutes(-1),now.AddMinutes(5),new(Signing(newSign,true),SecurityAlgorithms.RsaSha256));
        token.Header["typ"]="at+jwt";var inner=new JwtSecurityTokenHandler().WriteToken(token);
        if(Protection=="Signed")return inner;
        return new JsonWebTokenHandler().EncryptToken(inner,new(Encryption(newEncryption),Protection,"A256CBC-HS512"),new Dictionary<string,object>{{"typ","at+jwt"},{"cty","JWT"}});
    }
    public SecurityKey Signing(bool newer,bool privateKey)=>privateKey
        ?new RsaSecurityKey(newer?newSigning:oldSigning){KeyId=newer?"ring-sign-new":"ring-sign-old"}
        :new RsaSecurityKey((newer?newSigning:oldSigning).ExportParameters(false)){KeyId=newer?"ring-sign-new":"ring-sign-old"};
    public SecurityKey Decryption(bool newer)=>Protection=="RSA-OAEP"
        ?new RsaSecurityKey(newer?newDecrypt!:oldDecrypt!){KeyId=newer?"ring-decrypt-new":"ring-decrypt-old"}
        :new SymmetricSecurityKey(newer?newSecret!:oldSecret!){KeyId=newer?"ring-decrypt-new":"ring-decrypt-old"};
    private SecurityKey Encryption(bool newer)=>Protection=="RSA-OAEP"
        ?new RsaSecurityKey((newer?newDecrypt!:oldDecrypt!).ExportParameters(false)){KeyId=newer?"ring-decrypt-new":"ring-decrypt-old"}
        :Decryption(newer);
    public void Dispose()
    {
        Ring?.Dispose();oldSigning.Dispose();newSigning.Dispose();oldDecrypt?.Dispose();newDecrypt?.Dispose();
        if(oldSecret is not null)CryptographicOperations.ZeroMemory(oldSecret);if(newSecret is not null)CryptographicOperations.ZeroMemory(newSecret);
    }
}

/// <summary>Per-fixture deterministic UTC/monotonic controls; never changes host time or token validation's system clock.</summary>
public sealed class FixtureTimeProvider:TimeProvider
{
    private readonly object gate=new();private DateTimeOffset now=DateTimeOffset.UtcNow;private long timestamp;
    public override long TimestampFrequency=>TimeSpan.TicksPerSecond;
    public override DateTimeOffset GetUtcNow(){lock(gate)return now;}
    public override long GetTimestamp(){lock(gate)return timestamp;}
    public void Advance(TimeSpan elapsed){lock(gate){now+=elapsed;timestamp+=elapsed.Ticks;}}
}
