using Cehpalon.Engine.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Cehpalon.Engine.Identity.JwtBearer;

public enum JwtKeySource { PublicJwks, ProvidedKeys, AuthorityMetadata, RotatingKeyRing }
public enum JwtTokenProtection { Signed, EncryptedSigned }

/// <summary>Mutable configuration binding DTO. Freeze through JwtAuthenticationProfile before activation.</summary>
public sealed class JwtProfileSettings
{
    public string Scheme { get; set; } = "Bearer";
    public string Issuer { get; set; } = "";
    public string Audience { get; set; } = "";
    public string Algorithm { get; set; } = "";
    public string TokenType { get; set; } = "at+jwt";
    public JwtKeySource KeySource { get; set; }
    public string? Authority { get; set; }
    public string? MetadataAddress { get; set; }
    public JwtTokenProtection TokenProtection { get; set; }
    public string? KeyManagementAlgorithm { get; set; }
    public string? ContentEncryptionAlgorithm { get; set; }
}

/// <summary>One exact algorithm/key family per scheme; no unverified token-selected trust or key endpoints.</summary>
public sealed class JwtAuthenticationProfile
{
    public static JwtAuthenticationProfile FromConfiguration(IConfiguration section)
    {
        ArgumentNullException.ThrowIfNull(section);
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "Scheme", "Issuer", "Audience", "Algorithm", "TokenType", "KeySource", "Authority", "MetadataAddress", "TokenProtection", "KeyManagementAlgorithm", "ContentEncryptionAlgorithm" };
        var fields = section.GetChildren().Take(allowed.Count + 1).ToArray();
        if (fields.Length < 1 || fields.Length > allowed.Count || fields.Any(f => !allowed.Contains(f.Key) || f.GetChildren().Any()))
            throw new ArgumentException("Authentication profile configuration must contain only supported scalar fields.", nameof(section));
        return new(section.Get<JwtProfileSettings>() ?? throw new ArgumentException("Missing JWT profile configuration.", nameof(section)));
    }
    public JwtAuthenticationProfile(JwtProfileSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        // Reuse the identity contract's bounded/control/UTF-16 validation.
        var identity = new IdentitySnapshot(new(settings.Issuer, "profile"), settings.Scheme,
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddSeconds(1));
        Scheme = identity.AuthenticationScheme; Issuer = identity.Principal.Issuer;
        Audience = new PrincipalId(settings.Audience, "profile").Issuer;
        Algorithm = settings.Algorithm; Family = Algorithm switch
        {
            "RS256" or "RS384" or "RS512" or "PS256" or "PS384" or "PS512" => "RSA",
            "ES256" or "ES384" or "ES512" => "EC",
            "HS256" or "HS384" or "HS512" => "oct",
            _ => throw new ArgumentException("Unsupported signing algorithm. Select an explicit supported signed JWT profile.", nameof(settings))
        };
        TokenType = new IdentitySnapshot(new("profile", "profile"), settings.TokenType,
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddSeconds(1)).AuthenticationScheme;
        if (!Enum.IsDefined(settings.KeySource)) throw new ArgumentException("Unknown key source.", nameof(settings));
        KeySource = settings.KeySource;
        if (KeySource == JwtKeySource.AuthorityMetadata)
        {
            if (Family == "oct") throw new ArgumentException("Symmetric secrets must use a caller-provided key source.", nameof(settings));
            Authority = Https(settings.Authority, nameof(settings.Authority));
            if (settings.MetadataAddress is not null) MetadataAddress = Https(settings.MetadataAddress, nameof(settings.MetadataAddress));
            _ = Https(Issuer, nameof(settings.Issuer));
        }
        else if (settings.Authority is not null || settings.MetadataAddress is not null)
            throw new ArgumentException("Local profiles cannot configure metadata endpoints.", nameof(settings));
        if (KeySource == JwtKeySource.PublicJwks && Family == "oct")
            throw new ArgumentException("Public JWKS cannot contain symmetric signing secrets.", nameof(settings));
        if (!Enum.IsDefined(settings.TokenProtection)) throw new ArgumentException("Unknown token protection mode.", nameof(settings));
        TokenProtection = settings.TokenProtection;
        if (TokenProtection == JwtTokenProtection.EncryptedSigned)
        {
            if (settings.KeyManagementAlgorithm is not ("RSA-OAEP" or "dir") || settings.ContentEncryptionAlgorithm != "A256CBC-HS512")
                throw new ArgumentException("Select an explicitly supported JWE profile: RSA-OAEP or dir with A256CBC-HS512. No algorithm fallback is performed.", nameof(settings));
            KeyManagementAlgorithm = settings.KeyManagementAlgorithm; ContentEncryptionAlgorithm = settings.ContentEncryptionAlgorithm;
        }
        else if (settings.KeyManagementAlgorithm is not null || settings.ContentEncryptionAlgorithm is not null)
            throw new ArgumentException("Signed profiles cannot configure JWE algorithms.", nameof(settings));
    }
    public string Scheme { get; }
    public string Issuer { get; }
    public string Audience { get; }
    public string Algorithm { get; }
    public string TokenType { get; }
    public JwtKeySource KeySource { get; }
    public string? Authority { get; }
    public string? MetadataAddress { get; }
    public JwtTokenProtection TokenProtection { get; }
    public string? KeyManagementAlgorithm { get; }
    public string? ContentEncryptionAlgorithm { get; }
    internal string Family { get; }
    private static string Https(string? value, string parameter)
    {
        if (value is null || value.Length > 2048 || !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) ||
            !string.IsNullOrEmpty(uri.Query) || value.Any(char.IsControl))
            throw new ArgumentException("Configure an absolute HTTPS trust endpoint without credentials, query or fragment.", parameter);
        return value;
    }
}

public static class JwtAuthenticationRegistration
{
    /// <summary>Call only from a selected module factory. Key callbacks run once here, after profile validation.</summary>
    public static AuthenticationBuilder AddCehpalonJwtBearer(this AuthenticationBuilder builder,
        JwtAuthenticationProfile profile, Func<string>? publicJwks = null, Func<IEnumerable<SecurityKey>>? providedKeys = null,
        Func<IEnumerable<SecurityKey>>? decryptionKeys = null)
    {
        ArgumentNullException.ThrowIfNull(builder); ArgumentNullException.ThrowIfNull(profile);
        if (profile.KeySource == JwtKeySource.RotatingKeyRing)
            throw new ArgumentException("Rotating key rings require their distinct registration method.");
        if (profile.KeySource == JwtKeySource.PublicJwks && (publicJwks is null || providedKeys is not null) ||
            profile.KeySource == JwtKeySource.ProvidedKeys && (providedKeys is null || publicJwks is not null) ||
            profile.KeySource == JwtKeySource.AuthorityMetadata && (publicJwks is not null || providedKeys is not null))
            throw new ArgumentException("The selected key source requires exactly its matching trusted provider.");
        if ((profile.TokenProtection == JwtTokenProtection.EncryptedSigned) != (decryptionKeys is not null))
            throw new ArgumentException("Encrypted-signed profiles require a separate decryption-key provider; signed profiles cannot configure one.");
        var keys = profile.KeySource switch
        {
            JwtKeySource.PublicJwks => ProfileKeys.ReadPublicJwks(publicJwks!(), profile),
            JwtKeySource.ProvidedKeys => ProfileKeys.CopyProvided(providedKeys!(), profile),
            _ => []
        };
        var decrypt = decryptionKeys is null ? [] : JweKeys.Copy(decryptionKeys(), profile);
        foreach (var signingKey in keys)
            if (!JweKeys.IsSeparate(signingKey, decrypt)) throw new ArgumentException("Signing and decryption keys must use separate IDs and material.");
        return builder.AddJwtBearer(profile.Scheme, options =>
        {
            options.MapInboundClaims = false; options.IncludeErrorDetails = false; options.SaveToken = false;
            options.RequireHttpsMetadata = true;
            options.UseSecurityTokenValidators = false;
            options.TokenHandlers.Clear();
            options.TokenHandlers.Add(new ProfileTokenHandler(profile));
            if (profile.KeySource == JwtKeySource.AuthorityMetadata)
            {
                options.Authority = profile.Authority;
                if (profile.MetadataAddress is { } address) options.MetadataAddress = address;
            }
            options.TokenValidationParameters = CreateValidationParameters(profile, keys, decrypt);
        });
    }
    internal static TokenValidationParameters CreateValidationParameters(JwtAuthenticationProfile profile, SecurityKey[] keys, SecurityKey[] decrypt)
    {
        var byId = keys.ToDictionary(k => k.KeyId, StringComparer.Ordinal);
        var decryptById = decrypt.ToDictionary(k => k.KeyId, StringComparer.Ordinal);
        var validation = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true, ValidateIssuer = true, ValidIssuer = profile.Issuer,
                IssuerValidatorUsingConfiguration = (issuer, _, _, _) => StringComparer.Ordinal.Equals(issuer, profile.Issuer)
                    ? issuer : throw new SecurityTokenInvalidIssuerException("The token issuer is not trusted by this profile."),
                ValidateAudience = true, ValidAudience = profile.Audience, IgnoreTrailingSlashWhenValidatingAudience = false,
                ValidateLifetime = true, RequireExpirationTime = true, RequireSignedTokens = true,
                ClockSkew = TimeSpan.Zero, ValidAlgorithms = [profile.Algorithm], ValidTypes = [profile.TokenType],
                TryAllIssuerSigningKeys = false,
                AlgorithmValidator = (algorithm, key, token, _) => token is JsonWebToken { IsEncrypted: true } outer
                    ? profile.TokenProtection == JwtTokenProtection.EncryptedSigned && algorithm == profile.ContentEncryptionAlgorithm &&
                        outer.Alg == profile.KeyManagementAlgorithm && outer.Enc == profile.ContentEncryptionAlgorithm && key is SymmetricSecurityKey && key.KeySize == 512
                    : StringComparer.Ordinal.Equals(algorithm, profile.Algorithm) && ProfileKeys.IsCompatible(key, profile) && JweKeys.IsSeparate(key, decrypt)
            };
        if (profile.TokenProtection == JwtTokenProtection.EncryptedSigned)
            {
                validation.TokenDecryptionKeyResolver = (_, _, kid, _) => kid is not null && decryptById.TryGetValue(kid, out var key) ? [key] : [];
                validation.TryAllDecryptionKeys = false;
                validation.TokenReader = (text, _) => ProfileTokenHandler.Read(text, profile, false);
            }
        if (profile.KeySource != JwtKeySource.AuthorityMetadata)
                validation.IssuerSigningKeyResolver = (_, _, kid, _) => kid is not null && byId.TryGetValue(kid, out var key) ? [key] : [];
        return validation;
    }

}
