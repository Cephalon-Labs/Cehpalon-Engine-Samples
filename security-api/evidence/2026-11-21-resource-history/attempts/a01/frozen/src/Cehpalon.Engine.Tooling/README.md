# Experimental portable scaffolding CLI

This executable (`cehpalon`) is a bounded early slice of Engine issue #20. It
generates source-checkout consumers of unchanged Core, Composition and the typed
operation-registration generator. The default portable-request-reply profile is
an unprotected console example; small-api adds actual HTTPS/JWT HTTP and optional
GraphQL through the existing guarded tenant boundary and explicit fixture authority.
Current scaffolding requires exact stable SDK 11.0.100 with roll-forward and prerelease selection disabled; emitted JWT package references use 11.0.0.
No real IdP/provider, Worker or new runtime semantics are generated. Full #20 and
platform gates remain outstanding; #3 is not changed by this tool.

```text
cehpalon --help
cehpalon --version
cehpalon new --name DemoApp --output <new-directory> --engine-root <existing-engine-checkout> [--profile portable-request-reply|small-api]
cehpalon validate --config <file> [--profile portable-request-reply|small-api]
```

`CliApplication.Run(string[], TextWriter, TextWriter)` returns 0 for success, 2 for
usage/configuration rejection, and 3 for path/I/O/source failure. Results are JSON;
success goes to output and diagnostics to error. Unknown or duplicate options,
extra positional arguments, unsupported profiles and names outside
`[A-Z][A-Za-z0-9]{0,63}` are rejected. DOS device names CON/PRN/AUX/NUL/COM1-9/LPT1-9
are rejected on every OS. No shells, builds, installs, downloads or services run.

`validate` uses the same bounded Composition compiler and selected catalog as the
generated consumer. Portable uses support `core`, entrypoint `app` depending on core, and entrypoint
`optional` depending on core. Validation checks graph compatibility, not whether
application factories will succeed. Optional is a negative fixture whose consumer
factory throws if selected; no optional feature is implemented. Configuration is
UTF-8 and limited to Composition's 1 MiB bound; malformed bytes and invalid graphs
fail before activation.

Portable `new` writes exactly nine fixed files: Consumer.csproj, Program.cs, Catalog.cs,
appsettings.json, appsettings.off.json, global.json, NuGet.Config,
engine-source.json and README.md. The supplied Engine checkout must contain the
required source inputs with the supported SDK policy and official-only NuGet
source policy. Explicit Engine paths in XML are escaped; the generated project
references Core/Composition and includes CodeGeneration as an analyzer only.
Assembly names use `PortableConsumer.<Name>` and source uses the fixed namespace
`PortableConsumers.Generated` to avoid framework/Engine name collisions.
Source-root paths containing `%`, `$`, `@`, `;`, `*` or `?` are rejected because
XML escaping alone does not neutralize MSBuild expressions or item-list syntax.
Spaces, Unicode and XML-escaped ampersands do not receive this rejection.
Global/feed policy bytes are copied; no package graph is invented by generation.
The observed manifest hashes selected source inputs and states that it is not a
git attestation or complete build/input inventory. No git subprocess is invoked.

Small API writes exactly fourteen files: Consumer.csproj, Program.cs, SelfTest.cs,
FixtureHost.cs, Catalog.cs, ContractExport.cs, four appsettings variants (API-only, API+GraphQL,
GraphQL-only, all-off), global.json, NuGet.Config, engine-source.json and README.md.
It observes32selected Engine inputs including Identity/Tenancy/HTTP/GraphQL and
requires the existing exact JWT/GraphQL package-version policy. It embeds template
sources in the CLI assembly and does not read a Samples checkout at generation time.
`validate --profile small-api` rejects unsupported selected Worker/provider modules
before activation, in addition to Composition graph validation.

The generated Small API runtime has explicit `--self-test --output <new-report>`
for real localhost HTTPS/JWT/cross-tenant/disabled/cancellation/lifecycle fixture
checks. It reads all four emitted configurations. `--serve --config <json>
--certificate <user.pfx> --public-key <RS256-public.pem> --ready <new-ready.json>`
requires caller-provided trust, with PFX password optionally supplied through
CEHPALON_TLS_PASSWORD. It binds only HTTPS IPv4 loopback/ephemeral port, publishes
new-only complete readiness JSON, and accepts console `stop` +Enter or Ctrl+C for
owned cleanup. Off/invalid config constructs no WebApplication/store and reads no key files.
Only self-test generates ephemeral private fixture keys; none are output.
The normal server still uses the clearly documented synthetic alice/tenant-a,
bob/tenant-b membership source and20k memory-store fixture, not real IdP/provider
integration. Tokens must use the generated README's fixed issuer/audience/RS256/
at+jwt contract. Caller headers and correlation metadata grant no tenant authority.
Disabled GraphQL skips service registration and mapping; vendor package presence
is not activation. These checks do not replace the full Small API workload or timing
protocol. Compiler-only dependencies must remain absent from consumer runtime.

After deliberately building the generated consumer, its explicit command
`--export-contracts --config <json> --output <new-directory>` writes offline
transport artifacts. It validates the same Composition/capability plan before
schema construction or output. `manifest.json` is always present; enabled HTTP
adds `openapi.json` (OpenAPI3.1), enabled GraphQL adds actual vendor-printed
`schema.graphql`, all-off adds neither schema. The shared typed transport catalog
also drives runtime routes/fields; actual generated registration IDs are verified
using a throwing handler factory without invoking it. HTTP DTO schemas come from
the adapter's exact serializer policy and errors from its actual envelope factory.
Request schemas add the adapter's object-only root constraint; inline schema `$id`
resources preserve local `$ref` roots. Custom validators, CLR numeric bounds,
duplicate-name/Unicode/body checks and tenant authority are not fully expressed by
structural JSON schemas. Nullable response roots remain possible as Core permits.

Only an enabled GraphQL export constructs/disposes a schema service provider;
its counters disclose that work. This offline artifact command does not construct
WebApplication, read TLS keys, open listeners or execute handlers/authority. It does
not enable network schema/introspection endpoints or weaken authentication. Output
is a new atomically published directory with deterministic bytes and hashes;
observed path protections retain the trusted-parent/race limits below. Failures
retain actual schema/cleanup counters. The source-only CLI itself executes none
of this compiled consumer work.

Output must be a new directory with an already-existing parent. Existing files,
directories and observed symlink/reparse-point ancestry are rejected. Known
Windows device/extended path namespaces (`\\.\` and `\\?\`) are rejected for
source, output and configuration inputs before I/O, on every host. Known
Engine/Docs/Samples checkout roots and their non-.local descendants are protected;
ignored `.local` descendants are allowed for retained test fixtures. Outputs are
deterministic for the same name, explicit source root and observed source bytes;
they do not embed target directory, time or generated GUID. Random names are used
only for private sibling staging. Fixed files are created without overwrite and
the directory is published with a non-overwriting move. Failed publication does
not delete or merge the destination. Cleanup verifies the absolute owned staging
path and deletes only expected plain files; it never recursively deletes unknown
content. Unexpected staging changes retain the stage rather than traversing it.

These checks observe paths at several points; they do not hold OS-level directory
handles or serialize arbitrary external editors. A hostile concurrent ancestor or
staging replacement can race the checks. This is a local developer tool with
trusted source/output parents, not a filesystem sandbox or cross-process atomic
source snapshot. Abrupt process loss can retain staging. Source project references
can change after generation. Future proof must check actual source/build inputs.
Generated projects inherit ordinary SDK/MSBuild parent policy; the source/output
parents and inherited build customizations must be trusted.

The portable-request-reply consumer compiles config before factories, builds its generated
registry inside the enabled app factory, dispatches one echo operation, and reports
factory/handler/dispatch/disposal counters after cleanup. All-off dispatches no
work. Plain Core provides no tenant protection; Small API explicitly wires the
existing guarded dispatcher with fixture authority. Successful local generation or
build is not supported-Windows, hosted-CI, AOT/trimming, package-release or
production qualification. The internal file-operation seam is for deterministic
partial-write/publication-race contract tests, with no product test switches.
