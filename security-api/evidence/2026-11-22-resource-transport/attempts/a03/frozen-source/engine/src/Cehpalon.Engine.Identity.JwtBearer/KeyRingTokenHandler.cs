using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cehpalon.Engine.Identity.JwtBearer;

internal sealed class KeyRingTokenHandler : JsonWebTokenHandler
{
    private readonly JwtKeyRing ring;
    internal KeyRingTokenHandler(JwtKeyRing ring)
    { this.ring = ring; MapInboundClaims = false; MaximumTokenSizeInBytes = ProfileTokenHandler.TokenLimit; }
    public override Task<TokenValidationResult> ValidateTokenAsync(string token, TokenValidationParameters validationParameters)
    {
        try { _ = ProfileTokenHandler.Read(token, ring.Profile, true); }
        catch { return Task.FromResult(Invalid()); }
        return ValidatePinnedAsync((handler, local) => handler.ValidateTokenAsync(token, local), validationParameters);
    }

    public override Task<TokenValidationResult> ValidateTokenAsync(SecurityToken token, TokenValidationParameters validationParameters)
    {
        try
        {
            if (token is not JsonWebToken jwt) return Task.FromResult(Invalid());
            _ = ProfileTokenHandler.Read(jwt.EncodedToken, ring.Profile, true);
        }
        catch { return Task.FromResult(Invalid()); }
        return ValidatePinnedAsync((handler, local) => handler.ValidateTokenAsync(token, local), validationParameters);
    }

    private async Task<TokenValidationResult> ValidatePinnedAsync(Func<ProfileTokenHandler, TokenValidationParameters, Task<TokenValidationResult>> validate,
        TokenValidationParameters validationParameters)
    {
        if (validationParameters.SignatureValidator is not null || validationParameters.SignatureValidatorUsingConfiguration is not null)
            return Invalid();
        var snapshot = ring.Capture();
        if (snapshot is null) return Invalid();
        var local = validationParameters.Clone();
        // Validated SecurityToken.SigningKey is public and mutable. Request-local key copies prevent
        // its consumers (including host events) from changing the published snapshot without Publish.
        var signing = ProfileKeys.CopyProvided(snapshot.Signing, ring.Profile);
        var decrypt = ring.Profile.TokenProtection == JwtTokenProtection.EncryptedSigned ? JweKeys.Copy(snapshot.Decrypt, ring.Profile) : [];
        // Do not let the standard shared provider cache retain mutable request/result key objects.
        // Crypto implementations stay standard; only this optional ring validation uses an isolated factory.
        var crypto = new CryptoProviderFactory { CacheSignatureProviders = false };
        foreach (var key in signing.Concat(decrypt)) key.CryptoProviderFactory = crypto;
        local.CryptoProviderFactory = crypto;
        var pinned = JwtAuthenticationRegistration.CreateValidationParameters(ring.Profile, signing, decrypt);
        local.ConfigurationManager = null; local.ValidateWithLKG = false; local.RefreshBeforeValidation = false;
        local.IssuerSigningKey = null; local.IssuerSigningKeys = null; local.TokenDecryptionKey = null; local.TokenDecryptionKeys = null;
        local.IssuerSigningKeyResolverUsingConfiguration = null;
        local.IssuerSigningKeyResolver = pinned.IssuerSigningKeyResolver;
        local.TokenDecryptionKeyResolver = pinned.TokenDecryptionKeyResolver;
        local.AlgorithmValidator = pinned.AlgorithmValidator; local.TokenReader = pinned.TokenReader;
        local.TryAllIssuerSigningKeys = false; local.TryAllDecryptionKeys = false;
        var handler = new ProfileTokenHandler(ring.Profile);
        var result = await validate(handler, local).ConfigureAwait(false);
        return result.IsValid && !ring.IsCurrent(snapshot) ? Invalid() : result;
    }
    private static TokenValidationResult Invalid() => new() { IsValid = false,
        Exception = new SecurityTokenValidationException("The current key publication is unavailable or changed during validation.") };
}

public static class JwtKeyRingRegistration
{
    /// <summary>Call only from the selected security factory. The consumer owns and manages the returned ring.</summary>
    public static AuthenticationBuilder AddCehpalonJwtBearerKeyRing(this AuthenticationBuilder builder, Func<JwtKeyRing> keyRing)
    {
        ArgumentNullException.ThrowIfNull(builder); ArgumentNullException.ThrowIfNull(keyRing);
        var ring = keyRing() ?? throw new ArgumentException("The trusted key-ring factory returned null.", nameof(keyRing));
        var profile = ring.Profile;
        return builder.AddJwtBearer(profile.Scheme, options =>
        {
            options.MapInboundClaims = false; options.IncludeErrorDetails = false; options.SaveToken = false;
            options.RequireHttpsMetadata = true; options.UseSecurityTokenValidators = false;
            options.TokenHandlers.Clear(); options.TokenHandlers.Add(new KeyRingTokenHandler(ring));
            options.TokenValidationParameters = JwtAuthenticationRegistration.CreateValidationParameters(profile, [], []);
        });
    }
}
