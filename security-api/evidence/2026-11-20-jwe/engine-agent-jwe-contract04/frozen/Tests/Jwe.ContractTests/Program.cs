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
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

var output=Path.GetFullPath(args.Single(a=>a.StartsWith("--output=",StringComparison.Ordinal))[9..]);
if(File.Exists(output))throw new IOException("Retain prior results.");
var checks=new List<object>();var passed=0;var failed=0;
void Require(bool value){if(!value)throw new InvalidOperationException("JWE contract assertion failed.");}
async Task Check(string name,Func<Task> run){try{await run();passed++;checks.Add(new{name,passed=true});}catch(Exception error){failed++;checks.Add(new{name,passed=false,errorType=error.GetType().Name,message="JWE contract failed; no token/key data emitted"});}}
async Task<T> Throws<T>(Func<Task> run)where T:Exception{try{await run();}catch(T error){return error;}throw new InvalidOperationException("Expected "+typeof(T).Name);}
const string issuer="urn:fixture:jwe",audience="jwe-api";
using var signingRsa=RSA.Create(2048);using var encryptionRsa=RSA.Create(2048);using var wrongRsa=RSA.Create(2048);using var weakRsa=RSA.Create(1024);
var signer=new RsaSecurityKey(signingRsa){KeyId="signing-1"};var decryptRsa=new RsaSecurityKey(encryptionRsa){KeyId="decryption-rsa"};
var direct=new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(64)){KeyId="decryption-dir"};
JwtProfileSettings Settings(string alg="RSA-OAEP")=>new(){Scheme="jwe",Issuer=issuer,Audience=audience,Algorithm="RS256",TokenProtection=JwtTokenProtection.EncryptedSigned,KeyManagementAlgorithm=alg,ContentEncryptionAlgorithm="A256CBC-HS512",KeySource=JwtKeySource.ProvidedKeys};
JwtAuthenticationProfile Profile(string alg="RSA-OAEP")=>new(Settings(alg));
string Inner(string mutation="")
{
    var now=DateTime.UtcNow;var key=mutation=="wrong-signature"?new RsaSecurityKey(wrongRsa){KeyId="signing-1"}:signer;
    var jwt=new JwtSecurityToken(mutation=="issuer"?"urn:other":issuer,mutation=="audience"?"other":audience,[new("sub","alice")],now.AddMinutes(-5),mutation=="expired"?now.AddMinutes(-1):now.AddMinutes(5),mutation=="unsigned"?null:new SigningCredentials(key,mutation=="signature-algorithm"?"RS512":"RS256"));
    jwt.Header["typ"]=mutation=="inner-type"?"JWT":"at+jwt";if(mutation=="inner-kid")jwt.Header["kid"]="unknown";
    if(mutation=="inner-remote")jwt.Header["jku"]="https://attacker.invalid/jwks";
    if(mutation=="inner-cty")jwt.Header["cty"]="JWT";
    return new JwtSecurityTokenHandler().WriteToken(jwt);
}
string Encrypt(string inner,string alg="RSA-OAEP",string mutation="")
{
    SecurityKey key=alg=="dir"?direct:decryptRsa;
    if(mutation is "kid" or "missing-kid")key=alg=="dir"?new SymmetricSecurityKey(direct.Key){KeyId=mutation=="kid"?"unknown":null}:new RsaSecurityKey(encryptionRsa){KeyId=mutation=="kid"?"unknown":null};
    if(mutation=="wrong-decryption-key")key=alg=="dir"?new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(64)){KeyId=direct.KeyId}:new RsaSecurityKey(wrongRsa){KeyId=decryptRsa.KeyId};
    var header=new Dictionary<string,object>{{"typ",mutation=="outer-type"?"JWT":"at+jwt"},{"cty",mutation=="cty"?"not-jwt":"JWT"}};
    if(mutation=="remote")header["jku"]="https://attacker.invalid/jwks";
    if(mutation=="critical")header["crit"]=new[]{"new-extension"};
    if(mutation=="outer-issuer")header["iss"]="urn:spoofed";
    var credentials=new EncryptingCredentials(key,alg,"A256CBC-HS512");
    var result=mutation=="compression"?new JsonWebTokenHandler().EncryptToken(inner,credentials,"DEF",header):new JsonWebTokenHandler().EncryptToken(inner,credentials,header);
    if(mutation is "tampered-tag" or "tampered-ciphertext" or "duplicate-header" or "missing-cty")
    {
        var parts=result.Split('.');
        if(mutation=="missing-cty")
        {var obj=System.Text.Json.Nodes.JsonNode.Parse(Base64UrlEncoder.Decode(parts[0]))!;obj.AsObject().Remove("cty");parts[0]=Base64UrlEncoder.Encode(obj.ToJsonString());}
        if(mutation=="duplicate-header")parts[0]=Base64UrlEncoder.Encode(Base64UrlEncoder.Decode(parts[0]).Replace("\"alg\":", "\"alg\":\"RSA-OAEP\",\"alg\":",StringComparison.Ordinal));
        if(mutation=="tampered-tag"){var bytes=Base64UrlEncoder.DecodeBytes(parts[4]);bytes[0]^=1;parts[4]=Base64UrlEncoder.Encode(bytes);}
        if(mutation=="tampered-ciphertext"){var bytes=Base64UrlEncoder.DecodeBytes(parts[3]);bytes[0]^=1;parts[3]=Base64UrlEncoder.Encode(bytes);}
        result=string.Join('.',parts);
    }
    return result;
}
ServiceProvider Provider(JwtAuthenticationProfile profile,Func<IEnumerable<SecurityKey>>? signing=null,Func<IEnumerable<SecurityKey>>? decrypt=null)
{var services=new ServiceCollection();services.AddLogging();services.AddAuthentication(profile.Scheme).AddCehpalonJwtBearer(profile,providedKeys:signing??(()=>[signer]),decryptionKeys:decrypt??(()=>profile.KeyManagementAlgorithm=="dir"?[direct]:[decryptRsa]));return services.BuildServiceProvider();}
async Task<bool> Accept(string token,string alg="RSA-OAEP")
{
    using var provider=Provider(Profile(alg));using var scope=provider.CreateScope();var context=new DefaultHttpContext{RequestServices=scope.ServiceProvider};context.Request.Headers.Authorization="Bearer "+token;
    var source=new AspNetCoreJwtIdentitySource(new FixedContext(context),"jwe");return await source.ResolveAsync(default) is {Principal.Subject:"alice"};
}

foreach(var alg in new[]{"RSA-OAEP","dir"})await Check("actual nested signed JWE authenticates "+alg+" A256CBC-HS512",async()=>Require(await Accept(Encrypt(Inner(),alg),alg)));
foreach(var mutation in new[]{"wrong-signature","signature-algorithm","unsigned","issuer","audience","expired","inner-type","inner-kid","inner-remote","inner-cty"})
await Check("valid encryption rejects invalid inner "+mutation,async()=>Require(!await Accept(Encrypt(Inner(mutation)))));
foreach(var mutation in new[]{"wrong-decryption-key","outer-type","cty","missing-cty","remote","critical","outer-issuer","compression","kid","missing-kid","tampered-tag","tampered-ciphertext","duplicate-header"})
await Check("outer policy/authentication rejects "+mutation,async()=>Require(!await Accept(Encrypt(Inner(),mutation:mutation))));
await Check("encrypted profile rejects plain signed token",async()=>Require(!await Accept(Inner())));
await Check("signed profile rejects JWE without activating decryption provider",async()=>
{
    var s=Settings();s.TokenProtection=JwtTokenProtection.Signed;s.KeyManagementAlgorithm=s.ContentEncryptionAlgorithm=null;
    var services=new ServiceCollection();services.AddLogging();services.AddAuthentication("jwe").AddCehpalonJwtBearer(new(s),providedKeys:()=>[signer]);
    using var provider=services.BuildServiceProvider();using var scope=provider.CreateScope();var context=new DefaultHttpContext{RequestServices=scope.ServiceProvider};context.Request.Headers.Authorization="Bearer "+Encrypt(Inner());Require(!(await context.AuthenticateAsync("jwe")).Succeeded);
});
await Check("encrypted arbitrary JSON and encrypted-encrypted nesting never become authority",async()=>
{Require(!await Accept(Encrypt("{\"sub\":\"alice\"}")));Require(!await Accept(Encrypt(Encrypt(Inner()))));});
await Check("token and protected header bounds reject before validation",async()=>
{
    Require(!await Accept(new string('a',65537)));
    var inner=Inner();var header=new Dictionary<string,object>{{"typ","at+jwt"},{"cty","JWT"},{"padding",new string('a',5000)}};
    Require(!await Accept(new JsonWebTokenHandler().EncryptToken(inner,new EncryptingCredentials(decryptRsa,"RSA-OAEP","A256CBC-HS512"),header)));
});
await Check("SecurityToken overload keeps outer protection gate",async()=>
{
    using var provider=Provider(Profile());var options=provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get("jwe");var handler=options.TokenHandlers.Single();
    Require((await handler.ValidateTokenAsync(new JsonWebToken(Encrypt(Inner())),options.TokenValidationParameters)).IsValid);
    Require(!(await handler.ValidateTokenAsync(new JsonWebToken(Inner()),options.TokenValidationParameters)).IsValid);
});
await Check("authenticated encryption of a signed duplicate-header JWT rejects ambiguity",async()=>
{
    var existing=Inner().Split('.');var header=Base64UrlEncoder.Encode("{\"alg\":\"none\",\"alg\":\"RS256\",\"kid\":\"signing-1\",\"typ\":\"at+jwt\"}");
    var input=header+"."+existing[1];var signature=JwtTokenUtilities.CreateEncodedSignature(input,new SigningCredentials(signer,"RS256"));
    Require(!await Accept(Encrypt(input+"."+signature)));
});
await Check("decryption secret and RSA private keys are snapshotted independently of provider mutation/disposal",async()=>
{
    var bytes=RandomNumberGenerator.GetBytes(64);var local=new SymmetricSecurityKey(bytes){KeyId="local-dir"};
    var encrypted=new JsonWebTokenHandler().EncryptToken(Inner(),new EncryptingCredentials(local,"dir","A256CBC-HS512"),new Dictionary<string,object>{{"typ","at+jwt"},{"cty","JWT"}});
    using var directProvider=Provider(Profile("dir"),decrypt:()=>[local]);Array.Fill(bytes,(byte)0);local.KeyId="changed";
    var options=directProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get("jwe");Require((await options.TokenHandlers.Single().ValidateTokenAsync(encrypted,options.TokenValidationParameters)).IsValid);
    using var localRsa=RSA.Create(2048);var localKey=new RsaSecurityKey(localRsa){KeyId="local-rsa"};
    var wrapped=new JsonWebTokenHandler().EncryptToken(Inner(),new EncryptingCredentials(localKey,"RSA-OAEP","A256CBC-HS512"),new Dictionary<string,object>{{"typ","at+jwt"},{"cty","JWT"}});
    using var rsaProvider=Provider(Profile(),decrypt:()=>[localKey]);localRsa.Dispose();
    var rsaOptions=rsaProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get("jwe");Require((await rsaOptions.TokenHandlers.Single().ValidateTokenAsync(wrapped,rsaOptions.TokenValidationParameters)).IsValid);
});
foreach(var mutation in new[]{"RSA1_5","RSA-OAEP-256","A256GCM","missing-enc","signed-with-encryption","unknown-mode"})
await Check("unsupported protection configuration rejects before providers "+mutation,async()=>
{
    var calls=0;await Throws<ArgumentException>(()=>Task.Run(()=>{var s=Settings();
    if(mutation is "RSA1_5" or "RSA-OAEP-256")s.KeyManagementAlgorithm=mutation;
    if(mutation=="A256GCM")s.ContentEncryptionAlgorithm="A256GCM";
    if(mutation=="missing-enc")s.ContentEncryptionAlgorithm=null;
    if(mutation=="signed-with-encryption")s.TokenProtection=JwtTokenProtection.Signed;
    if(mutation=="unknown-mode")s.TokenProtection=(JwtTokenProtection)99;
    using var p=Provider(new(s),()=>{calls++;return [signer];},()=>{calls++;return [decryptRsa];});}));Require(calls==0);
});
foreach(var mutation in new[]{"duplicate-id","missing-id","public-only","weak-rsa","wrong-family","wrong-direct-size"})
await Check("decryption key configuration rejects "+mutation,async()=>
{
    var profile=Profile(mutation=="wrong-direct-size"?"dir":"RSA-OAEP");
    SecurityKey[] keys=mutation switch{"duplicate-id"=>[decryptRsa,decryptRsa],"missing-id"=>[new RsaSecurityKey(encryptionRsa)],"public-only"=>[new RsaSecurityKey(encryptionRsa.ExportParameters(false)){KeyId="public"}],"weak-rsa"=>[new RsaSecurityKey(weakRsa){KeyId="weak"}],"wrong-family"=>[direct],_=>[new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)){KeyId="short"}]};
    await Throws<ArgumentException>(()=>Task.Run(()=>{using var p=Provider(profile,decrypt:()=>keys);}));
});
await Check("signing/decryption key IDs cannot overlap despite different material",async()=>
{await Throws<ArgumentException>(()=>Task.Run(()=>{using var p=Provider(Profile(),decrypt:()=>[new RsaSecurityKey(encryptionRsa){KeyId="signing-1"}]);}));});
await Check("same RSA material cannot be reused with a different decryption kid",async()=>
{await Throws<ArgumentException>(()=>Task.Run(()=>{using var p=Provider(Profile(),decrypt:()=>[new RsaSecurityKey(signingRsa){KeyId="different-kid"}]);}));});
await Check("equivalent padded RSA exponent cannot bypass local material separation",async()=>
{
    var p=signingRsa.ExportParameters(false);var jwk=new JsonWebKey{Kty="RSA",Kid="other-signing-id",N=Base64UrlEncoder.Encode(p.Modulus!),E=Base64UrlEncoder.Encode(new byte[]{0}.Concat(p.Exponent!).ToArray()),Alg="RS256",Use="sig"};
    await Throws<ArgumentException>(()=>Task.Run(()=>{using var provider=Provider(Profile(),()=>[jwk],()=>[new RsaSecurityKey(signingRsa){KeyId="other-decrypt-id"}]);}));
    var privateParameters=signingRsa.ExportParameters(true);privateParameters.Exponent=new byte[]{0}.Concat(privateParameters.Exponent!).ToArray();
    await Throws<ArgumentException>(()=>Task.Run(()=>{using var provider=Provider(Profile(),decrypt:()=>[new RsaSecurityKey(privateParameters){KeyId="padded-private"}]);}));
});
await Check("same symmetric material cannot be reused for signature and decryption",async()=>
{
    var s=Settings("dir");s.Algorithm="HS512";
    await Throws<ArgumentException>(()=>Task.Run(()=>{using var p=Provider(new(s),()=>[new SymmetricSecurityKey(direct.Key){KeyId="different-signing-kid"}]);}));
});
await Check("metadata signing callback rejects reused actual RSA material and IDs",()=>
{
    var s=Settings();s.Issuer=s.Authority="https://issuer.example";s.KeySource=JwtKeySource.AuthorityMetadata;
    var services=new ServiceCollection();services.AddLogging();services.AddAuthentication("jwe").AddCehpalonJwtBearer(new(s),decryptionKeys:()=>[decryptRsa]);using var p=services.BuildServiceProvider();
    var tvp=p.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get("jwe").TokenValidationParameters;
    Require(!tvp.AlgorithmValidator("RS256",new RsaSecurityKey(encryptionRsa){KeyId="different"},new JsonWebToken(Inner()),tvp));
    Require(!tvp.AlgorithmValidator("RS256",new RsaSecurityKey(signingRsa){KeyId=decryptRsa.KeyId},new JsonWebToken(Inner()),tvp));return Task.CompletedTask;
});
await Check("metadata key separation compares RSA integers rather than encoded bytes",()=>
{
    var s=Settings();s.Issuer=s.Authority="https://issuer.example";s.KeySource=JwtKeySource.AuthorityMetadata;
    var services=new ServiceCollection();services.AddLogging();services.AddAuthentication("jwe").AddCehpalonJwtBearer(new(s),decryptionKeys:()=>[decryptRsa]);using var provider=services.BuildServiceProvider();
    var tvp=provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get("jwe").TokenValidationParameters;var pub=encryptionRsa.ExportParameters(false);pub.Exponent=new byte[]{0}.Concat(pub.Exponent!).ToArray();
    var jwk=new JsonWebKey{Kty="RSA",Kid="padded-metadata",N=Base64UrlEncoder.Encode(pub.Modulus!),E=Base64UrlEncoder.Encode(pub.Exponent!)};
    Require(!tvp.AlgorithmValidator("RS256",jwk,new JsonWebToken(Inner()),tvp));Require(!tvp.AlgorithmValidator("RS256",new RsaSecurityKey(pub){KeyId="padded-rsa-object"},new JsonWebToken(Inner()),tvp));return Task.CompletedTask;
});
await Check("metadata converted RsaSecurityKey cannot inflate actual RSA modulus strength",()=>
{
    var p=weakRsa.ExportParameters(false);var padded=new byte[128].Concat(p.Modulus!).ToArray();
    var metadata=JsonSerializer.Serialize(new{keys=new[]{new{kty="RSA",kid="padded-weak",use="sig",alg="RS256",n=Base64UrlEncoder.Encode(padded),e=Base64UrlEncoder.Encode(p.Exponent!)}}});
    var converted=new JsonWebKeySet(metadata).GetSigningKeys().Single();Require(converted is RsaSecurityKey&&converted.KeySize>=2048);
    using var provider=Provider(Profile());var tvp=provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get("jwe").TokenValidationParameters;
    Require(!tvp.AlgorithmValidator("RS256",converted,new JsonWebToken(Inner()),tvp));return Task.CompletedTask;
});
await Check("direct JWE rejects nonempty encrypted-key segment even when authentication tag is unchanged",async()=>
{
    var token=Encrypt(Inner(),"dir");Require(await Accept(token,"dir"));var parts=token.Split('.');Require(parts[1].Length==0);parts[1]="AQID";Require(!await Accept(string.Join('.',parts),"dir"));
});
await Check("missing or signed-profile decryption callbacks reject before any providers",async()=>
{
    var calls=0;var services=new ServiceCollection();var builder=services.AddAuthentication("jwe");
    await Throws<ArgumentException>(()=>Task.Run(()=>builder.AddCehpalonJwtBearer(Profile(),providedKeys:()=>{calls++;return [signer];})));
    var s=Settings();s.TokenProtection=JwtTokenProtection.Signed;s.KeyManagementAlgorithm=s.ContentEncryptionAlgorithm=null;
    await Throws<ArgumentException>(()=>Task.Run(()=>builder.AddCehpalonJwtBearer(new(s),providedKeys:()=>{calls++;return [signer];},decryptionKeys:()=>{calls++;return [decryptRsa];})));Require(calls==0);
});
await Check("appsettings freezes explicit encryption algorithms",()=>
{
    var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Scheme","jwe"},{"Issuer",issuer},{"Audience",audience},{"Algorithm","RS256"},{"KeySource","ProvidedKeys"},{"TokenProtection","EncryptedSigned"},{"KeyManagementAlgorithm","dir"},{"ContentEncryptionAlgorithm","A256CBC-HS512"}}).Build();
    var profile=JwtAuthenticationProfile.FromConfiguration(config);config["ContentEncryptionAlgorithm"]="A256GCM";Require(profile.TokenProtection==JwtTokenProtection.EncryptedSigned&&profile.ContentEncryptionAlgorithm=="A256CBC-HS512");return Task.CompletedTask;
});
await Check("disabled module does no signing or decryption key callback work",async()=>
{
    var calls=0;var services=new ServiceCollection();var compiled=CompositionCompiler.Compile("""{"Cehpalon":{"SchemaVersion":1,"Architecture":"Modular","Topology":"SingleProcess","Pattern":"RequestReply","Modules":{"security":{"Enabled":false}}}}""",[new("security",ModuleRole.Support)]);
    await using var lease=await PlanActivator.ActivateAsync(compiled.Plan!,[new("security",_=>{services.AddAuthentication("jwe").AddCehpalonJwtBearer(Profile(),providedKeys:()=>{calls++;return [signer];},decryptionKeys:()=>{calls++;return [decryptRsa];});return ValueTask.FromResult<IAsyncDisposable>(new Empty());})]);Require(calls==0&&services.Count==0);
});
Directory.CreateDirectory(Path.GetDirectoryName(output)!);await using(var file=new FileStream(output,FileMode.CreateNew))await JsonSerializer.SerializeAsync(file,new{passed,failed,checks});Console.WriteLine(JsonSerializer.Serialize(new{passed,failed,output}));return failed==0?0:1;
sealed class FixedContext(HttpContext context):IHttpContextAccessor{public HttpContext? HttpContext{get;set;}=context;}
sealed class Empty:IAsyncDisposable{public ValueTask DisposeAsync()=>ValueTask.CompletedTask;}
