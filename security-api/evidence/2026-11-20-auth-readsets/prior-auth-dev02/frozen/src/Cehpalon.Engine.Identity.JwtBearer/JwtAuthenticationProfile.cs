using Cehpalon.Engine.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace Cehpalon.Engine.Identity.JwtBearer;

public enum JwtKeySource { PublicJwks, ProvidedKeys, AuthorityMetadata }

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
}

/// <summary>One exact algorithm/key family per scheme; no unverified token-selected trust or key endpoints.</summary>
public sealed class JwtAuthenticationProfile
{
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
    }
    public string Scheme { get; }
    public string Issuer { get; }
    public string Audience { get; }
    public string Algorithm { get; }
    public string TokenType { get; }
    public JwtKeySource KeySource { get; }
    public string? Authority { get; }
    public string? MetadataAddress { get; }
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
        JwtAuthenticationProfile profile, Func<string>? publicJwks = null, Func<IEnumerable<SecurityKey>>? providedKeys = null)
    {
        ArgumentNullException.ThrowIfNull(builder); ArgumentNullException.ThrowIfNull(profile);
        if (profile.KeySource == JwtKeySource.PublicJwks && (publicJwks is null || providedKeys is not null) ||
            profile.KeySource == JwtKeySource.ProvidedKeys && (providedKeys is null || publicJwks is not null) ||
            profile.KeySource == JwtKeySource.AuthorityMetadata && (publicJwks is not null || providedKeys is not null))
            throw new ArgumentException("The selected key source requires exactly its matching trusted provider.");
        var keys = profile.KeySource switch
        {
            JwtKeySource.PublicJwks => ProfileKeys.ReadPublicJwks(publicJwks!(), profile),
            JwtKeySource.ProvidedKeys => ProfileKeys.CopyProvided(providedKeys!(), profile),
            _ => []
        };
        var byId = keys.ToDictionary(k => k.KeyId, StringComparer.Ordinal);
        return builder.AddJwtBearer(profile.Scheme, options =>
        {
            options.MapInboundClaims = false; options.IncludeErrorDetails = false; options.SaveToken = false;
            options.RequireHttpsMetadata = true;
            if (profile.KeySource == JwtKeySource.AuthorityMetadata)
            {
                options.Authority = profile.Authority; options.MetadataAddress = profile.MetadataAddress;
            }
            var validation = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true, ValidateIssuer = true, ValidIssuer = profile.Issuer,
                IssuerValidatorUsingConfiguration = (issuer, _, _, _) => StringComparer.Ordinal.Equals(issuer, profile.Issuer)
                    ? issuer : throw new SecurityTokenInvalidIssuerException("The token issuer is not trusted by this profile."),
                ValidateAudience = true, ValidAudience = profile.Audience, IgnoreTrailingSlashWhenValidatingAudience = false,
                ValidateLifetime = true, RequireExpirationTime = true, RequireSignedTokens = true,
                ClockSkew = TimeSpan.Zero, ValidAlgorithms = [profile.Algorithm], ValidTypes = [profile.TokenType],
                TryAllIssuerSigningKeys = false,
                AlgorithmValidator = (algorithm, key, _, _) => StringComparer.Ordinal.Equals(algorithm, profile.Algorithm) && ProfileKeys.IsCompatible(key, profile)
            };
            if (profile.KeySource != JwtKeySource.AuthorityMetadata)
                validation.IssuerSigningKeyResolver = (_, _, kid, _) => kid is not null && byId.TryGetValue(kid, out var key) ? [key] : [];
            options.TokenValidationParameters = validation;
        });
    }
}
