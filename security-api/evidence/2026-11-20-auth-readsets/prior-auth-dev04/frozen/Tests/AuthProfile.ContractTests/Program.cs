using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Identity.AspNetCore;
using Cehpalon.Engine.Identity.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

var output=Path.GetFullPath(args.Single(a=>a.StartsWith("--output=",StringComparison.Ordinal))[9..]);
if(File.Exists(output))throw new IOException("Use fresh retained output.");
var checks=new List<object>();var passed=0;var failed=0;
void Require(bool value){if(!value)throw new InvalidOperationException("Profile contract assertion failed.");}
async Task Check(string name,Func<Task> action)
{try{await action();passed++;checks.Add(new{name,passed=true});}catch(Exception error){failed++;checks.Add(new{name,passed=false,error=error.ToString()});}}
async Task<T> Throws<T>(Func<Task> action)where T:Exception
{try{await action();}catch(T error){return error;}throw new InvalidOperationException("Expected "+typeof(T).Name);}
const string issuer="urn:cehpalon:profile-fixture",audience="profile-api";
using var rsa=RSA.Create(2048);using var otherRsa=RSA.Create(2048);using var weakRsa=RSA.Create(1024);
using var ec=ECDsa.Create(ECCurve.NamedCurves.nistP256);
var rsaKey=new RsaSecurityKey(rsa){KeyId="rsa-1"};var ecKey=new ECDsaSecurityKey(ec){KeyId="ec-1"};
var secret=new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)){KeyId="hmac-1"};
JwtAuthenticationProfile Profile(string algorithm="RS256",JwtKeySource source=JwtKeySource.PublicJwks)=>new(new(){Scheme="fixture",Issuer=issuer,Audience=audience,Algorithm=algorithm,KeySource=source});
string PublicJwks(SecurityKey key,string algorithm)
{
    var jwk=key is RsaSecurityKey r?JsonWebKeyConverter.ConvertFromRSASecurityKey(r):JsonWebKeyConverter.ConvertFromECDsaSecurityKey((ECDsaSecurityKey)key);
    object values=jwk.Kty=="RSA"?new{kty=jwk.Kty,kid=key.KeyId,use="sig",alg=algorithm,n=jwk.N,e=jwk.E}:
        new{kty=jwk.Kty,kid=key.KeyId,use="sig",alg=algorithm,crv=jwk.Crv,x=jwk.X,y=jwk.Y};
    return JsonSerializer.Serialize(new{keys=new[]{values}});
}
string Token(SecurityKey? key,string algorithm="RS256",string tokenIssuer=issuer,string tokenAudience=audience,bool expired=false,string? kid=null)
{
    var now=DateTime.UtcNow;
    var jwt=new JwtSecurityToken(tokenIssuer,tokenAudience,[new("sub","alice")],now.AddMinutes(-2),expired?now.AddMinutes(-1):now.AddMinutes(2),key is null?null:new SigningCredentials(key,algorithm));
    jwt.Header["typ"]="at+jwt";if(kid is not null)jwt.Header["kid"]=kid;return new JwtSecurityTokenHandler().WriteToken(jwt);
}
ServiceProvider Provider(JwtAuthenticationProfile profile,Func<string>? jwks=null,Func<IEnumerable<SecurityKey>>? keys=null)
{
    var services=new ServiceCollection();services.AddLogging();services.AddAuthentication(profile.Scheme).AddCehpalonJwtBearer(profile,jwks,keys);return services.BuildServiceProvider();
}
async Task<bool> Accept(JwtAuthenticationProfile profile,string token,Func<string>? jwks=null,Func<IEnumerable<SecurityKey>>? keys=null)
{
    using var provider=Provider(profile,jwks,keys);using var scope=provider.CreateScope();
    var context=new DefaultHttpContext{RequestServices=scope.ServiceProvider};context.Request.Headers.Authorization="Bearer "+token;
    var source=new AspNetCoreJwtIdentitySource(new HttpContextAccessor{HttpContext=context},profile.Scheme);
    var result=await source.ResolveAsync(default);return result is not null&&result.Principal.Subject=="alice";
}

foreach(var algorithm in new[]{"RS256","PS256","ES256","HS256"})
await Check("actual established-handler signature validation "+algorithm,async()=>
{
    var key=algorithm=="ES256"?(SecurityKey)ecKey:algorithm=="HS256"?secret:rsaKey;
    var profile=Profile(algorithm,algorithm=="RS256"?JwtKeySource.PublicJwks:JwtKeySource.ProvidedKeys);
    Require(await Accept(profile,Token(key,algorithm),algorithm=="RS256"?()=>PublicJwks(key,algorithm):null,algorithm!="RS256"?()=>[key]:null));
});
await Check("provided public JWK snapshots and validates without diagnostic ToString parsing",async()=>
{
    var jwk=new JsonWebKey(JsonNode.Parse(PublicJwks(rsaKey,"RS256"))!["keys"]![0]!.ToJsonString());
    Require(await Accept(Profile(source:JwtKeySource.ProvidedKeys),Token(rsaKey),keys:()=>[jwk]));
});
foreach(var mutation in new[]{"wrong-key","wrong-algorithm","unsigned","issuer","audience","audience-slash","unknown-kid","expired"})
await Check("real JWT rejects "+mutation,async()=>
{
    var key=mutation=="wrong-key"?new RsaSecurityKey(otherRsa){KeyId="rsa-1"}:rsaKey;
    var token=Token(mutation=="unsigned"?null:key,mutation=="wrong-algorithm"?"RS512":"RS256",mutation=="issuer"?"urn:wrong":issuer,
        mutation=="audience"?"wrong":mutation=="audience-slash"?audience+"/":audience,mutation=="expired",mutation=="unknown-kid"?"unknown":null);
    Require(!await Accept(Profile(),token,()=>PublicJwks(rsaKey,"RS256")));
});
foreach(var mutation in new[]{"duplicate-kid","missing-kid","algorithm","private-field","remote-key-url","duplicate-field","weak-rsa","wrong-family","wrong-use","wrong-ops","malformed-base64","weak-exponent"})
await Check("public JWKS configuration rejects "+mutation,async()=>
{
    var node=JsonNode.Parse(PublicJwks(mutation=="weak-rsa"?new RsaSecurityKey(weakRsa){KeyId="weak"}:rsaKey,"RS256"))!;
    var key=node["keys"]![0]!;
    if(mutation=="duplicate-kid")node["keys"]!.AsArray().Add(key.DeepClone());
    if(mutation=="missing-kid")key["kid"]="";
    if(mutation=="algorithm")key["alg"]="RS512";
    if(mutation=="private-field")key["d"]="never-accepted";
    if(mutation=="remote-key-url")key["jku"]="https://attacker.invalid/key";
    if(mutation=="wrong-family")key["kty"]="oct";
    if(mutation=="wrong-use")key["use"]="enc";
    if(mutation=="wrong-ops")key["key_ops"]=new JsonArray("sign");
    if(mutation=="malformed-base64")key["n"]="bad+/=";
    if(mutation=="weak-exponent")key["e"]="Aw";
    var json=node.ToJsonString();if(mutation=="duplicate-field")json=json.Replace("\"kty\":\"RSA\"","\"kty\":\"RSA\",\"kty\":\"RSA\"",StringComparison.Ordinal);
    await Throws<ArgumentException>(()=>Task.Run(()=>{using var provider=Provider(Profile(),()=>json);}));
});
foreach(var mutation in new[]{"weak-secret","wrong-family","duplicate-id","missing-id","declared-algorithm"})
await Check("provided keys reject "+mutation,async()=>
{
    var profile=Profile(source:JwtKeySource.ProvidedKeys);
    SecurityKey[] keys=mutation=="weak-secret"?[new SymmetricSecurityKey(new byte[16]){KeyId="weak"}]:
        mutation=="wrong-family"?[ecKey]:mutation=="duplicate-id"?[rsaKey,rsaKey]:mutation=="missing-id"?[new RsaSecurityKey(rsa)]:[new JsonWebKey{Kty="RSA",Kid="jwk",N=JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaKey).N,E="AQAB",Alg="PS256"}];
    if(mutation=="weak-secret")profile=Profile("HS256",JwtKeySource.ProvidedKeys);
    await Throws<ArgumentException>(()=>Task.Run(()=>{using var provider=Provider(profile,keys:()=>keys);}));
});
await Check("mutable configuration and provided secret cannot alter frozen profile/key snapshot",async()=>
{
    var settings=new JwtProfileSettings{Scheme="fixture",Issuer=issuer,Audience=audience,Algorithm="HS256",KeySource=JwtKeySource.ProvidedKeys};var profile=new JwtAuthenticationProfile(settings);
    settings.Algorithm="none";settings.Issuer="urn:wrong";Require(profile.Algorithm=="HS256"&&profile.Issuer==issuer);
    var keyBytes=RandomNumberGenerator.GetBytes(32);var mutable=new SymmetricSecurityKey(keyBytes){KeyId="copy"};var token=Token(mutable,"HS256");
    using var provider=Provider(profile,keys:()=>[mutable]);Array.Fill(keyBytes,(byte)0);
    using var scope=provider.CreateScope();var context=new DefaultHttpContext{RequestServices=scope.ServiceProvider};context.Request.Headers.Authorization="Bearer "+token;
    Require((await context.AuthenticateAsync("fixture")).Succeeded);
});
await Check("metadata mode stays HTTPS with fixed validation and no local provider work",()=>
{
    var profile=new JwtAuthenticationProfile(new(){Scheme="metadata",Issuer="https://issuer.example/realm",Audience=audience,Algorithm="PS256",KeySource=JwtKeySource.AuthorityMetadata,Authority="https://issuer.example/realm"});
    using var provider=Provider(profile);var options=provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(profile.Scheme);
    Require(options.RequireHttpsMetadata&&options.Authority==profile.Authority&&options.TokenValidationParameters.ValidIssuer==profile.Issuer&&options.TokenValidationParameters.ValidAlgorithms!.Single()=="PS256");
    return Task.CompletedTask;
});
await Check("metadata cannot expand the exact configured token issuer",async()=>
{
    var profile=new JwtAuthenticationProfile(new(){Scheme="metadata",Issuer="https://wanted.example",Audience=audience,Algorithm="RS256",KeySource=JwtKeySource.AuthorityMetadata,Authority="https://metadata.example"});
    using var provider=Provider(profile);var validation=provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(profile.Scheme).TokenValidationParameters;
    var configuration=new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration{Issuer="https://other.example"};
    await Throws<SecurityTokenInvalidIssuerException>(()=>Task.Run(()=>validation.IssuerValidatorUsingConfiguration(configuration.Issuer,new JwtSecurityToken(),validation,configuration)));
    Require(validation.IssuerValidatorUsingConfiguration(profile.Issuer,new JwtSecurityToken(),validation,configuration)==profile.Issuer);
});
await Check("metadata padded weak RSA modulus is rejected despite inflated KeySize",()=>
{
    var profile=new JwtAuthenticationProfile(new(){Scheme="metadata",Issuer="https://wanted.example",Audience=audience,Algorithm="RS256",KeySource=JwtKeySource.AuthorityMetadata,Authority="https://metadata.example"});
    using var provider=Provider(profile);var validation=provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(profile.Scheme).TokenValidationParameters;
    var weak=JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(weakRsa){KeyId="padded"});
    var n=Base64UrlEncoder.DecodeBytes(weak.N);weak.N=Base64UrlEncoder.Encode(new byte[128].Concat(n).ToArray());
    Require(weak.KeySize>=2048&&!validation.AlgorithmValidator("RS256",weak,new JwtSecurityToken(),validation));return Task.CompletedTask;
});
foreach(var mutation in new[]{"none","unknown","public-secret","http-metadata","credential-url","mixed-source","metadata-local-callback"})
await Check("profile configuration fails closed "+mutation,async()=>
{
    var calls=0;
    await Throws<ArgumentException>(()=>Task.Run(()=>
    {
        var s=new JwtProfileSettings{Scheme="fixture",Issuer=issuer,Audience=audience,Algorithm=mutation=="none"?"none":mutation=="unknown"?"future-algorithm":mutation=="public-secret"?"HS256":"RS256",KeySource=JwtKeySource.PublicJwks};
        if(mutation is "http-metadata" or "credential-url" or "metadata-local-callback")
        {s.KeySource=JwtKeySource.AuthorityMetadata;s.Issuer="https://issuer.example";s.Authority=mutation=="http-metadata"?"http://issuer.example":mutation=="credential-url"?"https://user:secret@issuer.example":"https://issuer.example";}
        using var p=mutation=="mixed-source"?Provider(new(s),()=>{calls++;return PublicJwks(rsaKey,"RS256");},()=>{calls++;return [rsaKey];}):
            Provider(new(s),()=>{calls++;return PublicJwks(rsaKey,"RS256");});
    }));Require(calls==0);
});
await Check("disabled composition does not construct profile provider or authentication services",async()=>
{
    var calls=0;var services=new ServiceCollection();
    var compiled=CompositionCompiler.Compile("""{"Cehpalon":{"SchemaVersion":1,"Architecture":"Modular","Topology":"SingleProcess","Pattern":"RequestReply","Modules":{"security":{"Enabled":false}}}}""",[new("security",ModuleRole.Support)]);
    Require(compiled.IsSuccess);
    await using var lease=await PlanActivator.ActivateAsync(compiled.Plan!,[new("security",_=>
    {services.AddAuthentication("fixture").AddCehpalonJwtBearer(Profile(),()=>{calls++;return PublicJwks(rsaKey,"RS256");});return ValueTask.FromResult<IAsyncDisposable>(new Empty());})]);
    Require(calls==0&&services.Count==0);
});
await Check("generic authenticated ticket mapper accepts bounded cookie-style ticket",async()=>
{
    var fixture=new TicketFixture();Require(await fixture.Source().ResolveAsync(default) is {Principal.Subject:"alice",AuthenticationScheme:"Cookies"});
    fixture.Properties.ExpiresUtc=DateTimeOffset.UtcNow.AddMinutes(-1);Require(await fixture.Source().ResolveAsync(default) is null);
});
foreach(var mutation in new[]{"wrong-ticket-scheme","spoofed-flag","duplicate-subject","missing-expiry","wrong-mapped-scheme","expired-mapping","cancel-during-map","clock-rollback"})
await Check("generic ticket mapping rejects "+mutation,async()=>
{
    var f=new TicketFixture();var mapper=new Mapper();using var cts=new CancellationTokenSource();
    if(mutation=="wrong-ticket-scheme")f.TicketScheme="other";
    if(mutation=="spoofed-flag")f.NoResult=true;
    if(mutation=="duplicate-subject")f.Identity.AddClaim(new(ClaimTypes.NameIdentifier,"mallory"));
    if(mutation=="missing-expiry")f.Properties.ExpiresUtc=null;
    if(mutation=="wrong-mapped-scheme")mapper.Scheme="wrong";
    if(mutation=="expired-mapping")mapper.Expired=true;
    if(mutation=="cancel-during-map")mapper.Hook=()=>cts.Cancel();
    if(mutation=="clock-rollback")mapper.Hook=()=>f.Clock.Now=f.Clock.Now.AddSeconds(-1);
    var source=f.Source(mutation is "wrong-mapped-scheme" or "expired-mapping" or "cancel-during-map" or "clock-rollback"?mapper:null);
    if(mutation=="cancel-during-map")await Throws<OperationCanceledException>(async()=>await source.ResolveAsync(cts.Token));
    else Require(await source.ResolveAsync(default) is null);
    f.Dispose();
});
Directory.CreateDirectory(Path.GetDirectoryName(output)!);await using(var file=new FileStream(output,FileMode.CreateNew))await JsonSerializer.SerializeAsync(file,new{passed,failed,checks});
Console.WriteLine(JsonSerializer.Serialize(new{passed,failed,output}));return failed==0?0:1;

sealed class Empty:IAsyncDisposable{public ValueTask DisposeAsync()=>ValueTask.CompletedTask;}
sealed class Clock:TimeProvider{public DateTimeOffset Now=DateTimeOffset.UtcNow;public override DateTimeOffset GetUtcNow()=>Now;}
sealed class Mapper:IAuthenticatedTicketIdentityMapper
{
    public string Scheme="Cookies";public bool Expired;public Action? Hook;
    public IdentitySnapshot? Map(AuthenticationTicket ticket,string scheme,DateTimeOffset now)
    {Hook?.Invoke();return new(new("urn:cookie","alice"),Scheme,now.AddMinutes(-2),Expired?now.AddMinutes(-1):now.AddMinutes(1));}
}
sealed class TicketFixture:IAuthenticationService,IDisposable
{
    public readonly Clock Clock=new();public string TicketScheme="Cookies";public bool NoResult;
    public ClaimsIdentity Identity=new([new(ClaimTypes.NameIdentifier,"alice")],"cookie-handler");
    public AuthenticationProperties Properties=new(){IssuedUtc=DateTimeOffset.UtcNow.AddMinutes(-1),ExpiresUtc=DateTimeOffset.UtcNow.AddMinutes(1)};
    private ServiceProvider? provider;
    public AspNetCoreIdentitySource Source(IAuthenticatedTicketIdentityMapper? mapper=null)
    {
        provider??=new ServiceCollection().AddSingleton<IAuthenticationService>(this).BuildServiceProvider();
        var context=new DefaultHttpContext{RequestServices=provider,User=new(new ClaimsIdentity([new("sub","spoofed")],"spoofed"))};
        return new(new HttpContextAccessor{HttpContext=context},"Cookies",mapper??new TicketPropertyIdentityMapper("urn:cookie"),Clock);
    }
    public Task<AuthenticateResult> AuthenticateAsync(HttpContext context,string? scheme)=>Task.FromResult(NoResult?AuthenticateResult.NoResult():AuthenticateResult.Success(new(new ClaimsPrincipal(Identity),Properties,TicketScheme)));
    public Task ChallengeAsync(HttpContext c,string? s,AuthenticationProperties? p)=>throw new NotSupportedException();
    public Task ForbidAsync(HttpContext c,string? s,AuthenticationProperties? p)=>throw new NotSupportedException();
    public Task SignInAsync(HttpContext c,string? s,ClaimsPrincipal i,AuthenticationProperties? p)=>throw new NotSupportedException();
    public Task SignOutAsync(HttpContext c,string? s,AuthenticationProperties? p)=>throw new NotSupportedException();
    public void Dispose()=>provider?.Dispose();
}
