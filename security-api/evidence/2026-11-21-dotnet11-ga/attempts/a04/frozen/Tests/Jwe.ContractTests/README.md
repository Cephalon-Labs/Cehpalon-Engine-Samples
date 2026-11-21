# Nested signed JWE contracts

Pinned locked Release actual JwtBearer/IdentityModel authenticated decryption + signed-inner JWT checks for explicit RSA-OAEP and dir with A256CBC-HS512. Covers integrity/ciphertext/key/header/inner-signature/issuer/audience/lifetime failures, plaintext/encrypted profile separation, bounds, unsupported GCM/OAEP256, private-key representation, sign/decrypt material separation including padded RSA integers, metadata signature callback, key snapshots, strict direct encrypted-key segment, disabled providers and exact configuration.

Run through the root verifier after suite integration. Preserve fresh .local attempts/source copies; no actual keys/tokens/plaintext are emitted in result output. Root performs full suites and actual HTTPS consumer proof on Windows/WSL. Local fixtures do not establish real IdP/rotation/HSM/production qualification or a timing-oracle guarantee. No benchmark change.
