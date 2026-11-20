using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Cehpalon.Engine.Identity.JwtBearer;

internal static class ProfileKeys
{
    private static readonly HashSet<string> PublicFields = new(StringComparer.Ordinal)
        { "kty", "kid", "use", "key_ops", "alg", "n", "e", "crv", "x", "y" };

    internal static SecurityKey[] ReadPublicJwks(string json, JwtAuthenticationProfile profile)
    {
        ArgumentNullException.ThrowIfNull(json);
        if (json.Length > 65536 || Encoding.UTF8.GetByteCount(json) > 65536) throw new ArgumentException("Public JWKS exceeds 64 KiB.");
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1 ||
            !root.TryGetProperty("keys", out var array) || array.ValueKind != JsonValueKind.Array || array.GetArrayLength() is < 1 or > 16)
            throw new ArgumentException("Public JWKS must contain one keys array with 1 to 16 keys.");
        var keys = new List<SecurityKey>();
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) throw new ArgumentException("Invalid public JWK.");
            var fields = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in item.EnumerateObject())
                if (!PublicFields.Contains(property.Name) || !fields.Add(property.Name)) throw new ArgumentException("Unexpected or duplicate public JWK field.");
            string Value(string name) => item.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()! : throw new ArgumentException("Missing string public JWK field.");
            if (Value("kty") != profile.Family || Value("alg") != profile.Algorithm || Value("use") != "sig")
                throw new ArgumentException("Public JWK family, algorithm and signing use must match the configured profile.");
            if (item.TryGetProperty("key_ops", out var operations) && (operations.ValueKind != JsonValueKind.Array ||
                operations.GetArrayLength() != 1 || operations[0].ValueKind != JsonValueKind.String || operations[0].GetString() != "verify"))
                throw new ArgumentException("Public JWK key_ops must select verify only.");
            var key = new JsonWebKey(item.GetRawText());
            ValidatePublicMaterial(key, profile); keys.Add(key);
        }
        return RequireUnique(keys.ToArray(), profile);
    }

    internal static SecurityKey[] CopyProvided(IEnumerable<SecurityKey> input, JwtAuthenticationProfile profile)
    {
        ArgumentNullException.ThrowIfNull(input);
        var keys = input.Take(17).ToArray();
        if (keys.Length is < 1 or > 16 || keys.Any(k => k is null)) throw new ArgumentException("Provide 1 to 16 non-null keys.");
        var copy = new List<SecurityKey>();
        foreach (var key in keys)
        {
            if (key is JsonWebKey declared && !string.IsNullOrEmpty(declared.Alg) && declared.Alg != profile.Algorithm)
                throw new ArgumentException("Provided JWK declares a different algorithm.");
            if (key is JsonWebKey usage && (!string.IsNullOrEmpty(usage.Use) && usage.Use != "sig" || usage.KeyOps.Any(op => op != "verify")))
                throw new ArgumentException("Provided JWK must permit signature verification.");
            SecurityKey snapshot = key switch
            {
                RsaSecurityKey rsa => JsonWebKeyConverter.ConvertFromRSASecurityKey(rsa),
                ECDsaSecurityKey ec => JsonWebKeyConverter.ConvertFromECDsaSecurityKey(ec),
                SymmetricSecurityKey symmetric => new SymmetricSecurityKey(symmetric.Key.ToArray()),
                JsonWebKey jwk when jwk.Kty is "RSA" or "EC" => new JsonWebKey
                { Kty = jwk.Kty, N = jwk.N, E = jwk.E, Crv = jwk.Crv, X = jwk.X, Y = jwk.Y, Alg = jwk.Alg, Use = jwk.Use },
                _ => throw new ArgumentException("Use a supported RSA, EC or symmetric key from a trusted provider.")
            };
            snapshot.KeyId = key.KeyId;
            if (snapshot is JsonWebKey publicKey)
            {
                // Strip all private fields from provided signing-capable RSA/EC objects.
                publicKey.D = publicKey.P = publicKey.Q = publicKey.DP = publicKey.DQ = publicKey.QI = null;
                publicKey.Alg = profile.Algorithm; publicKey.Use = "sig";
                ValidatePublicMaterial(publicKey, profile);
            }
            copy.Add(snapshot);
        }
        return RequireUnique(copy.ToArray(), profile);
    }

    private static SecurityKey[] RequireUnique(SecurityKey[] keys, JwtAuthenticationProfile profile)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in keys)
            if (string.IsNullOrWhiteSpace(key.KeyId) || key.KeyId.Length > 128 || key.KeyId.Any(char.IsControl) ||
                !ids.Add(key.KeyId) || !IsCompatible(key, profile))
                throw new ArgumentException("Keys require unique bounded IDs and the configured algorithm family/strength.");
        return keys;
    }

    internal static bool IsCompatible(SecurityKey key, JwtAuthenticationProfile profile)
    {
        if (string.IsNullOrWhiteSpace(key.KeyId) || key.KeyId.Length > 128 || key.KeyId.Any(char.IsControl)) return false;
        var minimum = profile.Algorithm switch { "HS384" => 384, "HS512" => 512, _ => 256 };
        if (profile.Family == "oct") return key is SymmetricSecurityKey && key.KeySize >= minimum;
        if (key is JsonWebKey jwk)
        {
            if (jwk.Kty != profile.Family || !string.IsNullOrEmpty(jwk.Alg) && jwk.Alg != profile.Algorithm ||
                !string.IsNullOrEmpty(jwk.Use) && jwk.Use != "sig") return false;
            try
            {
                if (jwk.KeyOps.Any(op => op != "verify")) return false;
                if (profile.Family == "RSA")
                {
                    var n = Bytes(jwk.N, 1024); var e = Bytes(jwk.E, 4);
                    var exponent = new BigInteger(e, isUnsigned: true, isBigEndian: true);
                    return n[0] != 0 && new BigInteger(n, isUnsigned: true, isBigEndian: true).GetBitLength() >= 2048 && exponent >= 65537 && !exponent.IsEven;
                }
                var size = profile.Algorithm == "ES512" ? 66 : profile.Algorithm == "ES384" ? 48 : 32;
                return jwk.Crv == Curve(profile.Algorithm) && Bytes(jwk.X, 66).Length == size && Bytes(jwk.Y, 66).Length == size;
            }
            catch (ArgumentException) { return false; }
            catch (FormatException) { return false; }
        }
        return profile.Family == "RSA" && key is RsaSecurityKey && key.KeySize >= 2048 ||
            profile.Family == "EC" && key is ECDsaSecurityKey && key.KeySize == (profile.Algorithm == "ES512" ? 521 : profile.Algorithm == "ES384" ? 384 : 256);
    }

    private static string Curve(string algorithm) => algorithm switch { "ES256" => "P-256", "ES384" => "P-384", "ES512" => "P-521", _ => "" };
    private static byte[] Bytes(string? value, int maximum)
    {
        if (string.IsNullOrEmpty(value) || value.Length > maximum * 2 || value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            throw new ArgumentException("Invalid bounded base64url public key field.");
        var bytes = Base64UrlEncoder.DecodeBytes(value);
        if (bytes.Length > maximum || Base64UrlEncoder.Encode(bytes) != value) throw new ArgumentException("Noncanonical public key field.");
        return bytes;
    }
    private static void ValidatePublicMaterial(JsonWebKey key, JwtAuthenticationProfile profile)
    {
        if (key.Kty != profile.Family) throw new ArgumentException("Key family mismatch.");
        if (key.Kty == "RSA")
        {
            var n = Bytes(key.N, 1024); var e = Bytes(key.E, 4);
            var exponent = new BigInteger(e, isUnsigned: true, isBigEndian: true);
            if (n[0] == 0 || new BigInteger(n, isUnsigned: true, isBigEndian: true).GetBitLength() < 2048 || exponent < 65537 || exponent.IsEven)
                throw new ArgumentException("RSA public key is too weak or malformed.");
            using var rsa = RSA.Create(); rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });
        }
        else if (key.Kty == "EC")
        {
            var curve = Curve(profile.Algorithm); var size = curve == "P-521" ? 66 : curve == "P-384" ? 48 : 32;
            var x = Bytes(key.X, 66); var y = Bytes(key.Y, 66);
            if (key.Crv != curve || x.Length != size || y.Length != size) throw new ArgumentException("EC curve/point must match the algorithm.");
            using var ec = ECDsa.Create(new ECParameters { Curve = curve == "P-521" ? ECCurve.NamedCurves.nistP521 : curve == "P-384" ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y } });
        }
        else throw new ArgumentException("Public JWKS supports RSA/EC verification keys only.");
    }
}
