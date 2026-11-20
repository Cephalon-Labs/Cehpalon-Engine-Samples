using System.Numerics;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Cehpalon.Engine.Identity.JwtBearer;

internal static class JweKeys
{
    internal static SecurityKey[] Copy(IEnumerable<SecurityKey> values, JwtAuthenticationProfile profile)
    {
        ArgumentNullException.ThrowIfNull(values);
        var keys = values.Take(17).ToArray();
        if (keys.Length is < 1 or > 16 || keys.Any(k => k is null)) throw new ArgumentException("Provide 1 to 16 decryption keys.");
        var copy = new List<SecurityKey>(); var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in keys)
        {
            if (string.IsNullOrWhiteSpace(key.KeyId) || key.KeyId.Length > 128 || key.KeyId.Any(char.IsControl) || !ids.Add(key.KeyId))
                throw new ArgumentException("Decryption keys require unique bounded IDs.");
            if (profile.KeyManagementAlgorithm == "dir" && key is SymmetricSecurityKey secret && secret.KeySize == 512)
                copy.Add(new SymmetricSecurityKey(secret.Key.ToArray()) { KeyId = key.KeyId });
            else if (profile.KeyManagementAlgorithm == "RSA-OAEP" && key is RsaSecurityKey rsa)
            {
                try
                {
                    var p = rsa.Rsa is null ? rsa.Parameters : rsa.Rsa.ExportParameters(true);
                    var snapshot = new RSAParameters { Modulus = p.Modulus?.ToArray(), Exponent = p.Exponent?.ToArray(), D = p.D?.ToArray(),
                        DP = p.DP?.ToArray(), DQ = p.DQ?.ToArray(), P = p.P?.ToArray(), Q = p.Q?.ToArray(), InverseQ = p.InverseQ?.ToArray() };
                    if (snapshot.Modulus is null || snapshot.Modulus.Length is < 256 or > 1024 || snapshot.Modulus[0] == 0 ||
                        new BigInteger(snapshot.Modulus, true, true).GetBitLength() < 2048 || snapshot.D is null)
                        throw new ArgumentException("RSA decryption requires an exportable private key of at least 2048 actual bits.");
                    using var check = RSA.Create(); check.ImportParameters(snapshot);
                    copy.Add(new RsaSecurityKey(snapshot) { KeyId = key.KeyId });
                }
                catch (CryptographicException) { throw new ArgumentException("Invalid or non-exportable RSA decryption key."); }
            }
            else throw new ArgumentException("Decryption key family/size does not match the configured JWE profile.");
        }
        return copy.ToArray();
    }

    internal static bool IsSeparate(SecurityKey signingKey, SecurityKey[] decryptionKeys)
    {
        foreach (var decrypt in decryptionKeys)
        {
            if (StringComparer.Ordinal.Equals(signingKey.KeyId, decrypt.KeyId)) return false;
            if (signingKey is SymmetricSecurityKey signingSecret && decrypt is SymmetricSecurityKey decryptSecret &&
                CryptographicOperations.FixedTimeEquals(signingSecret.Key, decryptSecret.Key)) return false;
            if (decrypt is RsaSecurityKey rsa)
            {
                var p = rsa.Parameters;
                if (signingKey is JsonWebKey { Kty: "RSA" } jwk && jwk.N == Base64UrlEncoder.Encode(p.Modulus!) && jwk.E == Base64UrlEncoder.Encode(p.Exponent!)) return false;
                if (signingKey is RsaSecurityKey signer)
                {
                    var s = signer.Rsa is null ? signer.Parameters : signer.Rsa.ExportParameters(false);
                    if (s.Modulus is not null && s.Exponent is not null && s.Modulus.AsSpan().SequenceEqual(p.Modulus) && s.Exponent.AsSpan().SequenceEqual(p.Exponent)) return false;
                }
            }
        }
        return true;
    }
}
