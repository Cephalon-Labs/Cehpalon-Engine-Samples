using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;
using Cehpalon.Engine.Transports.Http;
using Cehpalon.Engine.Transports.GraphQL;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.IdentityModel.Tokens;

namespace SecurityApi;

public sealed class JwtFixture : IDisposable
{
    public const string Issuer="urn:cehpalon:small-api-fixture", Audience="cehpalon-small-api-fixture";
    private readonly RSA key=RSA.Create(2048);
    public SecurityKey PublicKey => new RsaSecurityKey(key.ExportParameters(false)){KeyId="fixture-rsa"};
    public string PublicJwks()=>System.Text.Json.JsonSerializer.Serialize(new{keys=new[]{new{kty="RSA",kid="fixture-rsa",use="sig",alg="RS256",n=Base64UrlEncoder.Encode(key.ExportParameters(false).Modulus!),e=Base64UrlEncoder.Encode(key.ExportParameters(false).Exponent!)}}});
    public string Token(string subject="alice",string issuer=Issuer,string audience=Audience,bool expired=false,bool duplicateSubject=false,string type="at+jwt",string algorithm=SecurityAlgorithms.RsaSha256,string? kid=null)
    {
        var now=DateTime.UtcNow;
        var claims=new List<Claim>{new("sub",subject)};
        if(duplicateSubject) claims.Add(new("sub","mallory"));
        var token=new JwtSecurityToken(issuer,audience,claims,now.AddMinutes(-5),expired?now.AddMinutes(-1):now.AddMinutes(5),new SigningCredentials(new RsaSecurityKey(key){KeyId="fixture-rsa"},algorithm));
        token.Header["typ"]=type;
        if(kid is not null)token.Header["kid"]=kid;
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    public static bool ExactClaims(ClaimsPrincipal principal)
    {
        if(One(principal,"iss")!=Issuer || One(principal,"sub") is not {Length:>0 and <=256} subject
            || !long.TryParse(One(principal,"nbf"),NumberStyles.None,CultureInfo.InvariantCulture,out var start)
            || !long.TryParse(One(principal,"exp"),NumberStyles.None,CultureInfo.InvariantCulture,out var end)) return false;
        try { _=new IdentitySnapshot(new(Issuer,subject),JwtBearerDefaults.AuthenticationScheme,DateTimeOffset.FromUnixTimeSeconds(start),DateTimeOffset.FromUnixTimeSeconds(end)); return true; }
        catch(ArgumentException) { return false; }
    }
    public static string? One(ClaimsPrincipal principal,string type) { var values=principal.FindAll(type).Take(2).ToArray(); return values.Length==1?values[0].Value:null; }
    public void Dispose()=>key.Dispose();
}

public sealed class TlsFixture : IDisposable
{
    private readonly RSA rootKey=RSA.Create(2048),leafKey=RSA.Create(2048);
    public X509Certificate2 Root {get;}
    public X509Certificate2 Server {get;}
    public TlsFixture()
    {
        var now=DateTimeOffset.UtcNow;
        var ca=new CertificateRequest("CN=Cehpalon Small API fixture CA",rootKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        ca.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
        ca.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));
        Root=ca.CreateSelfSigned(now.AddMinutes(-5),now.AddHours(2));
        var leaf=new CertificateRequest("CN=localhost",leafKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        leaf.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
        leaf.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature,true));
        leaf.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new("1.3.6.1.5.5.7.3.1")},true));
        var san=new SubjectAlternativeNameBuilder();san.AddDnsName("localhost");san.AddIpAddress(IPAddress.Loopback);leaf.CertificateExtensions.Add(san.Build());
        using var cert=leaf.Create(Root,now.AddMinutes(-2),now.AddHours(1),RandomNumberGenerator.GetBytes(16));
        using var keyed=cert.CopyWithPrivateKey(leafKey);
        Server=X509CertificateLoader.LoadPkcs12(keyed.Export(X509ContentType.Pfx),null,OperatingSystem.IsWindows()?X509KeyStorageFlags.UserKeySet:X509KeyStorageFlags.EphemeralKeySet);
    }
    public HttpClient Client(Uri address,string? wrongHost=null)
    {
        var chain=new X509ChainPolicy{TrustMode=X509ChainTrustMode.CustomRootTrust,RevocationMode=X509RevocationMode.NoCheck};chain.CustomTrustStore.Add(Root);
        var handler=new SocketsHttpHandler{UseProxy=false,SslOptions=new SslClientAuthenticationOptions{CertificateChainPolicy=chain}};
        if(wrongHost is not null) handler.ConnectCallback=async(_,ct)=>{var socket=new Socket(SocketType.Stream,ProtocolType.Tcp);await socket.ConnectAsync(IPAddress.Loopback,address.Port,ct);return new NetworkStream(socket,true);};
        return new(handler){BaseAddress=wrongHost is null?address:new Uri($"https://{wrongHost}:{address.Port}"),Timeout=TimeSpan.FromSeconds(10)};
    }
    public void Dispose(){Server.Dispose();Root.Dispose();leafKey.Dispose();rootKey.Dispose();}
}

