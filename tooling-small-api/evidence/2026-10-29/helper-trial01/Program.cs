using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

var folder = Path.GetFullPath(args.Single());
if (Directory.Exists(folder)) throw new IOException("Use a new private fixture directory.");
Directory.CreateDirectory(folder);
if (OperatingSystem.IsWindows())
{
    var sid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException();
    var security = new DirectorySecurity();
    security.SetOwner(sid);
    security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
    security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
    new DirectoryInfo(folder).SetAccessControl(security);
    var observed = new DirectoryInfo(folder).GetAccessControl();
    var rules = observed.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
    if (!observed.AreAccessRulesProtected || rules.Length != 1 || rules[0].IdentityReference != sid
        || rules[0].AccessControlType != AccessControlType.Allow || rules[0].FileSystemRights != FileSystemRights.FullControl)
        throw new InvalidOperationException("Private fixture DACL is not owner-only.");
}
else
{
    File.SetUnixFileMode(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    if (File.GetUnixFileMode(folder) != (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute))
        throw new InvalidOperationException("Private fixture directory is not Unix0700.");
}
var password = Environment.GetEnvironmentVariable("CEHPALON_TLS_PASSWORD") ?? throw new InvalidOperationException();
using var caKey = RSA.Create(2048);
var caRequest = new CertificateRequest("CN=Cehpalon generated-serve proof CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
var now = DateTimeOffset.UtcNow;
using var ca = caRequest.CreateSelfSigned(now.AddMinutes(-2), now.AddHours(1));
using var leafKey = RSA.Create(2048);
var leafRequest = new CertificateRequest("CN=localhost", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost"); san.AddIpAddress(IPAddress.Loopback);
leafRequest.CertificateExtensions.Add(san.Build());
using var leaf = leafRequest.Create(ca, now.AddMinutes(-1), now.AddMinutes(20), RandomNumberGenerator.GetBytes(16));
using var server = leaf.CopyWithPrivateKey(leafKey);
File.WriteAllBytes(Path.Combine(folder, "server.pfx"), server.Export(X509ContentType.Pfx, password));
File.WriteAllText(Path.Combine(folder, "root-ca.pem"), ca.ExportCertificatePem());
using var jwt = RSA.Create(2048);
using var wrong = RSA.Create(2048);
File.WriteAllText(Path.Combine(folder, "jwt-public.pem"), jwt.ExportSubjectPublicKeyInfoPem());
string Base64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
string Token(string subject, RSA key)
{
    var header = Base64(JsonSerializer.SerializeToUtf8Bytes(new { alg = "RS256", typ = "at+jwt" }));
    var payload = Base64(JsonSerializer.SerializeToUtf8Bytes(new { iss = "urn:cehpalon:small-api-fixture", aud = "cehpalon-small-api-fixture",
        sub = subject, nbf = now.AddMinutes(-1).ToUnixTimeSeconds(), exp = now.AddMinutes(10).ToUnixTimeSeconds() }));
    var unsigned = header + "." + payload;
    return unsigned + "." + Base64(key.SignData(Encoding.ASCII.GetBytes(unsigned), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
}
File.WriteAllText(Path.Combine(folder, "material.json"), JsonSerializer.Serialize(new { alice = Token("alice", jwt), bob = Token("bob", jwt),
    untrusted = Token("alice", wrong), scope = "Ephemeral synthetic generated-serve proof material only; no production credentials" }));
if (!OperatingSystem.IsWindows())
    foreach (var path in Directory.EnumerateFiles(folder))
    {
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        if (File.GetUnixFileMode(path) != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
            throw new InvalidOperationException("Private fixture file is not Unix0600.");
    }
Console.WriteLine(JsonSerializer.Serialize(new { status = "created", permissionsVerified = true,
    permissions = OperatingSystem.IsWindows() ? "owner-only protected DACL" : "Unix0700 directory and0600 files",
    scope = "Ephemeral private fixture; keys, password and tokens not printed" }));
