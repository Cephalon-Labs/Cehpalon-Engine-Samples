using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cehpalon.Engine.Identity.JwtBearer;

/// <summary>Policy envelope checks over the established parser; all crypto and claim validation remain in IdentityModel.</summary>
internal sealed class ProfileTokenHandler : JsonWebTokenHandler
{
    internal const int TokenLimit = 65536;
    private readonly JwtAuthenticationProfile profile;
    internal ProfileTokenHandler(JwtAuthenticationProfile profile)
    { this.profile = profile; MapInboundClaims = false; MaximumTokenSizeInBytes = TokenLimit; }

    public override Task<TokenValidationResult> ValidateTokenAsync(string token, TokenValidationParameters validationParameters)
    {
        try { _ = Read(token, profile, true); }
        catch (Exception) { return Task.FromResult(Invalid()); }
        return base.ValidateTokenAsync(token, validationParameters);
    }
    public override async Task<TokenValidationResult> ValidateTokenAsync(SecurityToken token, TokenValidationParameters validationParameters)
    {
        try
        {
            if (token is not JsonWebToken jwt) return Invalid();
            _ = Read(jwt.EncodedToken, profile, true);
        }
        catch (Exception) { return Invalid(); }
        var result = await base.ValidateTokenAsync(token, validationParameters).ConfigureAwait(false);
        if (result.IsValid && profile.TokenProtection == JwtTokenProtection.EncryptedSigned &&
            result.SecurityToken is not JsonWebToken { IsEncrypted: true, InnerToken: { IsEncrypted: false, IsSigned: true } })
            return Invalid();
        return result;
    }
    private static TokenValidationResult Invalid() => new() { IsValid = false,
        Exception = new SecurityTokenValidationException("The token does not match the configured protection profile.") };

    internal static JsonWebToken Read(string token, JwtAuthenticationProfile profile, bool outer)
    {
        if (string.IsNullOrEmpty(token) || token.Length > TokenLimit) throw new SecurityTokenValidationException("Invalid bounded token.");
        var jwt = new JsonWebToken(token);
        if (outer && (profile.TokenProtection == JwtTokenProtection.EncryptedSigned) != jwt.IsEncrypted)
            throw new SecurityTokenValidationException("Token protection mode mismatch.");
        if (profile.TokenProtection != JwtTokenProtection.EncryptedSigned) return jwt;
        if (jwt.EncodedHeader.Length > 8192) throw new SecurityTokenValidationException("Protected header exceeds its bound.");
        var headerBytes = Base64UrlEncoder.DecodeBytes(jwt.EncodedHeader);
        if (headerBytes.Length > 4096) throw new SecurityTokenValidationException("Protected header exceeds its bound.");
        using var document = JsonDocument.Parse(headerBytes, new JsonDocumentOptions { MaxDepth = 4 });
        var names = new HashSet<string>(StringComparer.Ordinal);
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new SecurityTokenValidationException("Invalid protected header.");
        foreach (var field in document.RootElement.EnumerateObject())
        {
            var allowed = jwt.IsEncrypted ? field.Name is "alg" or "enc" or "kid" or "typ" or "cty"
                : field.Name is "alg" or "kid" or "typ" or "x5t" or "x5t#S256";
            if (!allowed || !names.Add(field.Name) || field.Value.ValueKind != JsonValueKind.String)
                throw new SecurityTokenValidationException("Unsupported or ambiguous protected header.");
        }
        if (string.IsNullOrWhiteSpace(jwt.Kid) || jwt.Kid.Length > 128 || jwt.Kid.Any(char.IsControl) || jwt.Typ != profile.TokenType)
            throw new SecurityTokenValidationException("Protected header identity/type mismatch.");
        if (jwt.IsEncrypted)
        {
            if (jwt.Alg != profile.KeyManagementAlgorithm || jwt.Enc != profile.ContentEncryptionAlgorithm || jwt.Cty != "JWT")
                throw new SecurityTokenValidationException("JWE algorithms/content type mismatch.");
            if (jwt.Alg == "dir" ? !string.IsNullOrEmpty(jwt.EncryptedKey) : string.IsNullOrEmpty(jwt.EncryptedKey))
                throw new SecurityTokenValidationException("JWE encrypted-key segment does not match its key-management profile.");
        }
        else if (!jwt.IsSigned || jwt.Alg != profile.Algorithm)
            throw new SecurityTokenValidationException("A signed inner JWT is required.");
        return jwt;
    }
}
