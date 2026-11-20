using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Identity.AspNetCore;
using Cehpalon.Engine.Identity.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

var output=Path.GetFullPath(args.Single(a=>a.StartsWith("--output=",StringComparison.Ordinal))[9..]);
if(File.Exists(output))throw new IOException("Retain previous results.");
var checks=new List<object>();var passed=0;var failed=0;
void Require(bool value){if(!value)throw new InvalidOperationException("Key-ring contract assertion failed.");}
async Task Check(string name,Func<Task> action)
{try{await action();passed++;checks.Add(new{name,passed=true});}catch(Exception error){failed++;checks.Add(new{name,passed=false,errorType=error.GetType().Name,message="Key-ring contract failed; key/token/credential details omitted"});}}
async Task<T> Throws<T>(Func<Task> action)where T:Exception
{try{await action();}catch(T error){return error;}throw new InvalidOperationException("Expected "+typeof(T).Name);}
const string issuer="urn:fixture:keyring",audience="keyring-api";
using var oldRsa=RSA.Create(2048);using var newRsa=RSA.Create(2048);using var oldDecryptRsa=RSA.Create(2048);using var newDecryptRsa=RSA.Create(2048);
var oldSign=new RsaSecurityKey(oldRsa){KeyId="sign-old"};var newSign=new RsaSecurityKey(newRsa){KeyId="sign-new"};
var oldDecrypt=new RsaSecurityKey(oldDecryptRsa){KeyId="decrypt-old"};var newDecrypt=new RsaSecurityKey(newDecryptRsa){KeyId="decrypt-new"};
var oldSecret=new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(64)){KeyId="direct-old"};var newSecret=new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(64)){KeyId="direct-new"};
JwtAuthenticationProfile Profile(string mode="Signed")=>new(new(){Scheme="ring",Issuer=issuer,Audience=audience,Algorithm="RS256",KeySource=JwtKeySource.RotatingKeyRing,
    TokenProtection=mode=="Signed"?JwtTokenProtection.Signed:JwtTokenProtection.EncryptedSigned,KeyManagementAlgorithm=mode=="Signed"?null:mode,ContentEncryptionAlgorithm=mode=="Signed"?null:"A256CBC-HS512"});
string Token(SecurityKey signing,SecurityKey? encryption=null,string mode="Signed")
{
    var now=DateTime.UtcNow;var jwt=new JwtSecurityToken(issuer,audience,[new("sub","alice")],now.AddMinutes(-5),now.AddMinutes(20),new SigningCredentials(signing,"RS256"));jwt.Header["typ"]="at+jwt";
    var inner=new JwtSecurityTokenHandler().WriteToken(jwt);
    return encryption is null?inner:new JsonWebTokenHandler().EncryptToken(inner,new(encryption,mode,"A256CBC-HS512"),new Dictionary<string,object>{{"typ","at+jwt"},{"cty","JWT"}});
}
long Publish(JwtKeyRing ring,SecurityKey[] signing,SecurityKey[]? decrypt=null,Clock? clock=null)
{var now=clock?.Now??DateTimeOffset.UtcNow;return ring.Publish(ring.Version,signing,decrypt,now.AddSeconds(-1),now.AddMinutes(1));}
ServiceProvider Provider(JwtKeyRing ring)
{var services=new ServiceCollection();services.AddLogging();services.AddAuthentication(ring.Profile.Scheme).AddCehpalonJwtBearerKeyRing(()=>ring);return services.BuildServiceProvider();}
async Task<bool> Accept(ServiceProvider provider,string token,CancellationToken cancellationToken=default)
{
    using var scope=provider.CreateScope();var context=new DefaultHttpContext{RequestServices=scope.ServiceProvider};context.Request.Headers.Authorization="Bearer "+token;
    var source=new AspNetCoreJwtIdentitySource(new FixedContext(context),"ring");return await source.ResolveAsync(cancellationToken) is {Principal.Subject:"alice"};
}

foreach(var mode in new[]{"Signed","RSA-OAEP","dir"})await Check("old/new overlap and independent retirement "+mode,async()=>
{
    using var ring=new JwtKeyRing(Profile(mode));var d0=mode=="dir"?(SecurityKey)oldSecret:oldDecrypt;var d1=mode=="dir"?(SecurityKey)newSecret:newDecrypt;
    Publish(ring,[oldSign],mode=="Signed"?null:[d0]);using var provider=Provider(ring);
    var oldToken=Token(oldSign,mode=="Signed"?null:d0,mode);var newToken=Token(newSign,mode=="Signed"?null:d1,mode);
    Require(await Accept(provider,oldToken)&&!await Accept(provider,newToken));
    Publish(ring,[oldSign,newSign],mode=="Signed"?null:[d0,d1]);Require(await Accept(provider,oldToken)&&await Accept(provider,newToken));
    Publish(ring,[newSign],mode=="Signed"?null:[d0,d1]);Require(!await Accept(provider,oldToken)&&await Accept(provider,newToken));
    if(mode!="Signed")
    {
        var oldDecryptNewSign=Token(newSign,d0,mode);Require(await Accept(provider,oldDecryptNewSign));
        Publish(ring,[newSign],[d1]);Require(!await Accept(provider,oldDecryptNewSign)&&await Accept(provider,newToken));
    }
});
await Check("new signing material with same kid cannot hit previous crypto cache",async()=>
{
    using var ring=new JwtKeyRing(Profile());var first=new RsaSecurityKey(oldRsa){KeyId="stable"};var second=new RsaSecurityKey(newRsa){KeyId="stable"};
    Publish(ring,[first]);using var provider=Provider(ring);var oldToken=Token(first);var nextToken=Token(second);Require(await Accept(provider,oldToken));
    Publish(ring,[second]);Require(!await Accept(provider,oldToken)&&await Accept(provider,nextToken));
});
await Check("empty ring denies until explicit publication",async()=>
{
    using var ring=new JwtKeyRing(Profile());using var provider=Provider(ring);Require(ring.Version==0&&!await Accept(provider,Token(oldSign)));
    Publish(ring,[oldSign]);Require(ring.Version==1&&await Accept(provider,Token(oldSign)));
});
await Check("withdrawal denies fresh validation and explicit new publication recovers",async()=>
{
    using var ring=new JwtKeyRing(Profile());Publish(ring,[oldSign]);using var provider=Provider(ring);var token=Token(oldSign);Require(await Accept(provider,token));
    var version=ring.Withdraw(ring.Version);Require(version==2&&!await Accept(provider,token));Publish(ring,[newSign]);Require(!await Accept(provider,token)&&await Accept(provider,Token(newSign)));
});
await Check("dispose permanently denies and closes publication",async()=>
{
    var ring=new JwtKeyRing(Profile());Publish(ring,[oldSign]);using var provider=Provider(ring);ring.Dispose();ring.Dispose();
    Require(!await Accept(provider,Token(oldSign)));await Throws<ObjectDisposedException>(()=>Task.Run(()=>Publish(ring,[newSign])));
    await Throws<ObjectDisposedException>(()=>Task.Run(()=>ring.Withdraw(ring.Version)));
});
foreach(var mutation in new[]{"empty","duplicate","wrong-family","weak","too-many","future","expired","too-long","decrypt-in-signed","enumeration-failure"})
await Check("invalid publication preserves active snapshot/version "+mutation,async()=>
{
    using var ring=new JwtKeyRing(Profile());Publish(ring,[oldSign]);using var provider=Provider(ring);var version=ring.Version;var now=DateTimeOffset.UtcNow;
    var keys=mutation switch{"empty"=>Array.Empty<SecurityKey>(),"duplicate"=>[newSign,newSign],"wrong-family"=>[oldSecret],"weak"=>[new SymmetricSecurityKey(new byte[16]){KeyId="weak"}],"too-many"=>Enumerable.Range(0,17).Select(i=>(SecurityKey)new RsaSecurityKey(newRsa){KeyId="key-"+i}).ToArray(),_=>new SecurityKey[]{newSign}};
    if(mutation=="enumeration-failure")await Throws<IOException>(()=>Task.Run(()=>ring.Publish(version,ThrowKeys(),null,now.AddSeconds(-1),now.AddMinutes(1))));
    else await Throws<ArgumentException>(()=>Task.Run(()=>ring.Publish(version,keys,mutation=="decrypt-in-signed"?[oldDecrypt]:null,
        now.AddSeconds(mutation=="future"?1:-1),mutation=="expired"?now.AddSeconds(-1):mutation=="too-long"?now.AddHours(2):now.AddMinutes(1))));
    Require(ring.Version==version&&await Accept(provider,Token(oldSign))&&!await Accept(provider,Token(newSign)));
});
foreach(var mutation in new[]{"missing","wrong-family","short-secret","same-id","same-material"})
await Check("invalid encrypted candidate preserves both roles "+mutation,async()=>
{
    var mode=mutation=="short-secret"?"dir":"RSA-OAEP";using var ring=new JwtKeyRing(Profile(mode));var decrypt=mode=="dir"?(SecurityKey)oldSecret:oldDecrypt;
    Publish(ring,[oldSign],[decrypt]);using var provider=Provider(ring);var before=ring.Version;
    SecurityKey[]? next=mutation=="missing"?null:mutation=="wrong-family"?[oldSecret]:mutation=="short-secret"?[new SymmetricSecurityKey(new byte[32]){KeyId="short"}]:
        mutation=="same-id"?[new RsaSecurityKey(newDecryptRsa){KeyId=newSign.KeyId}]:[new RsaSecurityKey(newRsa){KeyId="alias"}];
    await Throws<ArgumentException>(()=>Task.Run(()=>Publish(ring,[newSign],next)));
    Require(ring.Version==before&&await Accept(provider,Token(oldSign,decrypt,mode)));
});
await Check("stale CAS publishers cannot overwrite a newer snapshot",async()=>
{
    using var ring=new JwtKeyRing(Profile());Publish(ring,[oldSign]);using var provider=Provider(ring);var stale=ring.Version;
    Publish(ring,[newSign]);await Throws<InvalidOperationException>(()=>Task.Run(()=>ring.Publish(stale,[oldSign],null,DateTimeOffset.UtcNow.AddSeconds(-1),DateTimeOffset.UtcNow.AddMinutes(1))));
    await Throws<InvalidOperationException>(()=>Task.Run(()=>ring.Withdraw(stale)));
    Require(ring.Version==2&&!await Accept(provider,Token(oldSign))&&await Accept(provider,Token(newSign)));
});
await Check("concurrent expected-version publishers have exactly one winner",async()=>
{
    using var ring=new JwtKeyRing(Profile());Publish(ring,[oldSign]);var expected=ring.Version;using var ready=new Barrier(2);
    Task<bool> Update(SecurityKey key)=>Task.Run(()=>{ready.SignalAndWait(TimeSpan.FromSeconds(5));try{ring.Publish(expected,[key],null,DateTimeOffset.UtcNow.AddSeconds(-1),DateTimeOffset.UtcNow.AddMinutes(1));return true;}catch(InvalidOperationException){return false;}});
    var results=await Task.WhenAll(Update(oldSign),Update(newSign));Require(results.Count(x=>x)==1&&ring.Version==2);
    using var provider=Provider(ring);Require((await Accept(provider,Token(oldSign)))!=(await Accept(provider,Token(newSign))));
});
await Check("provided symmetric decryption mutation cannot change published snapshot",async()=>
{
    var bytes=RandomNumberGenerator.GetBytes(64);var mutable=new SymmetricSecurityKey(bytes){KeyId="mutable"};var token=Token(oldSign,mutable,"dir");
    using var ring=new JwtKeyRing(Profile("dir"));Publish(ring,[oldSign],[mutable]);Array.Fill(bytes,(byte)0);mutable.KeyId="changed";
    using var provider=Provider(ring);Require(await Accept(provider,token));
});
await Check("provided signing JWK/list mutation cannot alter published snapshot",async()=>
{
    var original=JsonWebKeyConverter.ConvertFromRSASecurityKey(oldSign);var list=new List<SecurityKey>{original};using var ring=new JwtKeyRing(Profile());Publish(ring,list.ToArray());
    original.N="Aw";original.Kid="changed";list.Clear();using var provider=Provider(ring);Require(await Accept(provider,Token(oldSign)));
});
foreach(var change in new[]{"expiry","utc-rollback","timestamp-rollback","partial-timestamp-rollback","negative-elapsed","clock-fault"})
await Check("snapshot validity invalidity latches "+change,async()=>
{
    var clock=new Clock();using var ring=new JwtKeyRing(Profile(),timeProvider:clock);Publish(ring,[oldSign],clock:clock);using var provider=Provider(ring);var token=Token(oldSign);Require(await Accept(provider,token));
    if(change=="partial-timestamp-rollback"){clock.Timestamp=100;Require(await Accept(provider,token));clock.Timestamp=50;}
    else if(change=="expiry")clock.Now=clock.Now.AddMinutes(2);
    else if(change=="utc-rollback")clock.Now=clock.Now.AddSeconds(-1);
    else if(change is "timestamp-rollback" or "negative-elapsed")clock.Timestamp=-1;
    else clock.Fail=true;
    Require(!await Accept(provider,token));clock.Fail=false;clock.Now=DateTimeOffset.UtcNow;clock.Timestamp=200;Require(!await Accept(provider,token));
    Publish(ring,[oldSign],clock:clock);Require(await Accept(provider,token));
});
await Check("monotonic elapsed cap expires even when UTC stalls",async()=>
{
    var clock=new Clock();using var ring=new JwtKeyRing(Profile(),timeProvider:clock);Publish(ring,[oldSign],clock:clock);using var provider=Provider(ring);Require(await Accept(provider,Token(oldSign)));
    clock.Timestamp=61*clock.TimestampFrequency;Require(!await Accept(provider,Token(oldSign)));
});
foreach(var change in new[]{"publish","withdraw","dispose","expiry","invalid-candidate"})
await Check("in-flight completion checks pinned version and validity "+change,async()=>
{
    var clock=new Clock();using var ring=new JwtKeyRing(Profile(),timeProvider:clock);Publish(ring,[oldSign],clock:clock);using var provider=Provider(ring);
    using var entered=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
    provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get("ring").TokenValidationParameters.LifetimeValidator=(_,_,_,_)=>{entered.Set();if(!release.Wait(TimeSpan.FromSeconds(10)))throw new TimeoutException();return true;};
    var validation=Task.Run(()=>Accept(provider,Token(oldSign)));
    try
    {
        Require(entered.Wait(TimeSpan.FromSeconds(10)));
        if(change=="publish")Publish(ring,[newSign],clock:clock);
        else if(change=="withdraw")ring.Withdraw(ring.Version);
        else if(change=="dispose")ring.Dispose();
        else if(change=="expiry")clock.Now=clock.Now.AddMinutes(2);
        else await Throws<ArgumentException>(()=>Task.Run(()=>Publish(ring,[])));
    }
    finally{release.Set();}
    Require(await validation== (change=="invalid-candidate"));
});
await Check("cached same-request ticket is distinct from fresh validation after withdrawal",async()=>
{
    using var ring=new JwtKeyRing(Profile());Publish(ring,[oldSign]);using var provider=Provider(ring);using var scope=provider.CreateScope();
    var context=new DefaultHttpContext{RequestServices=scope.ServiceProvider};var token=Token(oldSign);context.Request.Headers.Authorization="Bearer "+token;
    Require((await context.AuthenticateAsync("ring")).Succeeded);ring.Withdraw(ring.Version);
    Require((await context.AuthenticateAsync("ring")).Succeeded&&!await Accept(provider,token));
});
await Check("returned signing-key mutation cannot alter the active publication",async()=>
{
    foreach(var mode in new[]{"Signed","RSA-OAEP"})
    {
        using var ring=new JwtKeyRing(Profile(mode));Publish(ring,[oldSign],mode=="Signed"?null:[oldDecrypt]);using var provider=Provider(ring);
        var options=provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get("ring");var token=Token(oldSign,mode=="Signed"?null:oldDecrypt,mode);
        var result=await options.TokenHandlers.Single().ValidateTokenAsync(token,options.TokenValidationParameters);Require(result.IsValid);
        var parsed=(JsonWebToken)result.SecurityToken;var key=(JsonWebKey)(parsed.IsEncrypted?parsed.InnerToken.SigningKey:parsed.SigningKey);
        key.N="Aw";key.Kid="mutated-result";Require(ring.Version==1&&await Accept(provider,token));
    }
});
foreach(var kind in new[]{"ordinary","configuration"})await Check("inherited signature override cannot accept retired signer "+kind,async()=>
{
    using var ring=new JwtKeyRing(Profile());Publish(ring,[oldSign]);using var provider=Provider(ring);var token=Token(oldSign);
    Publish(ring,[newSign]);var options=provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get("ring");
    JsonWebToken Fake(string text){var parsed=new JsonWebToken(text);parsed.SigningKey=oldSign;return parsed;}
    if(kind=="ordinary")options.TokenValidationParameters.SignatureValidator=(text,_)=>Fake(text);
    else options.TokenValidationParameters.SignatureValidatorUsingConfiguration=(text,_,_)=>Fake(text);
    Require(!await Accept(provider,token)&&!await Accept(provider,Token(newSign)));
});
await Check("caller cancellation occurs before authentication/ring validation",async()=>
{
    using var ring=new JwtKeyRing(Profile());Publish(ring,[oldSign]);using var provider=Provider(ring);using var cts=new CancellationTokenSource();cts.Cancel();
    await Throws<OperationCanceledException>(async()=>await Accept(provider,Token(oldSign),cts.Token));
});
await Check("static registration rejects ring mode before any key callback",async()=>
{
    var calls=0;var services=new ServiceCollection();await Throws<ArgumentException>(()=>Task.Run(()=>services.AddAuthentication().AddCehpalonJwtBearer(Profile(),providedKeys:()=>{calls++;return [oldSign];})));
    Require(calls==0);
});
await Check("non-ring profiles and invalid lifetime cannot construct a ring",async()=>
{
    var nonRing=new JwtAuthenticationProfile(new(){Scheme="static",Issuer=issuer,Audience=audience,Algorithm="RS256",KeySource=JwtKeySource.ProvidedKeys});
    await Throws<ArgumentException>(()=>Task.Run(()=>new JwtKeyRing(nonRing)));
    await Throws<ArgumentOutOfRangeException>(()=>Task.Run(()=>new JwtKeyRing(Profile(),TimeSpan.Zero)));
    await Throws<ArgumentOutOfRangeException>(()=>Task.Run(()=>new JwtKeyRing(Profile(),TimeSpan.FromHours(2))));
});
await Check("disabled composition does not invoke ring factory",async()=>
{
    var calls=0;var services=new ServiceCollection();var compiled=CompositionCompiler.Compile("""{"Cehpalon":{"SchemaVersion":1,"Architecture":"Modular","Topology":"SingleProcess","Pattern":"RequestReply","Modules":{"security":{"Enabled":false}}}}""",[new("security",ModuleRole.Support)]);
    await using var lease=await PlanActivator.ActivateAsync(compiled.Plan!,[new("security",_=>{services.AddAuthentication().AddCehpalonJwtBearerKeyRing(()=>{calls++;return new(Profile());});return ValueTask.FromResult<IAsyncDisposable>(new Empty());})]);Require(calls==0&&services.Count==0);
});
Directory.CreateDirectory(Path.GetDirectoryName(output)!);await using(var file=new FileStream(output,FileMode.CreateNew))await JsonSerializer.SerializeAsync(file,new{passed,failed,checks});
Console.WriteLine(JsonSerializer.Serialize(new{passed,failed,output}));return failed==0?0:1;

IEnumerable<SecurityKey> ThrowKeys(){yield return newSign;throw new IOException("fixture provider failure");}
sealed class FixedContext(HttpContext context):IHttpContextAccessor{public HttpContext? HttpContext{get;set;}=context;}
sealed class Empty:IAsyncDisposable{public ValueTask DisposeAsync()=>ValueTask.CompletedTask;}
sealed class Clock:TimeProvider
{
    public DateTimeOffset Now=DateTimeOffset.UtcNow;public long Timestamp;public bool Fail;
    public override long TimestampFrequency=>1000;
    public override DateTimeOffset GetUtcNow()=>Fail?throw new InvalidOperationException("fixture clock"):Now;
    public override long GetTimestamp()=>Timestamp;
}
