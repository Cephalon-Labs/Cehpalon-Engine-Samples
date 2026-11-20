# Optional access/audit evidence

Pinned Engine and consumer source revisions are in summary.json. All final raw component/consumer outputs, locked build logs, source/dependency digests and actual emitted registries are retained per host. Prior development/launch failures are separate and never promoted to final acceptance. No binaries, certificates, signing keys, bearer tokens or machine traces are included.

The initial standalone component attempt retained raw build/test output but did not snapshot every executing source byte. Later verifier manifests freeze source digests. WSL launch failure occurred before a verifier manifest existed; failure.txt describes the Git pointer boundary. Windows/WSL final source hashes and emitted registry digests match exactly.

The initial packaging guard rejected inherited Git text conversion before commit. A scoped evidence/.gitattributes -text rule preserves the retained raw bytes; every staged digest is checked against SHA256SUMS. No test or capture was repeated for packaging.
