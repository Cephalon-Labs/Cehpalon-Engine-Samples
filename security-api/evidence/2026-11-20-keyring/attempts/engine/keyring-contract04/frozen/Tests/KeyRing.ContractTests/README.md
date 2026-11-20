# Local rotating JWT/JWE key-ring contracts

Run with the repository-pinned SDK and a fresh output path:

```powershell
dotnet restore Tests/KeyRing.ContractTests/KeyRing.ContractTests.csproj --locked-mode
dotnet run --project Tests/KeyRing.ContractTests -c Release -- --output=.local/keyring-contracts.json
```

The executable uses ephemeral standard IdentityModel RSA/HMAC/JWE cryptography. It checks signed, RSA-OAEP and dir overlap/retirement; coherent expected-version publication; stale/concurrent/invalid publisher behavior; key-copy isolation; validity latches; disposal/withdrawal; in-flight completion checks; unsupported signature-override rejection; and disabled-composition factory avoidance. Returned JWK conversion/parameter mutation is followed by bounded parallel fresh validation of correct and wrong signers, with per-validation non-caching factory assertions. The HMAC case checks the standard key getter's byte-copy isolation, not mutation of its underlying key.

The in-flight gate uses a trusted host lifetime-validator fixture. The same-context authentication-cache case deliberately records the boundary: completed tickets can remain cached after withdrawal, while a new context denies. Cancellation is checked before authentication through the existing identity source. No benchmark, external provider, distributed revocation, tenant authorization or production-acceptance claim follows from this executable. Results contain check names/counts and sanitized exception types, never keys or tokens; prior outputs are preserved.
