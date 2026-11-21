# Experimental HTTP operation adapter

This net11.0 adapter maps explicit typed JSON POST bindings onto ASP.NET Core routing. It references Core and the shared ASP.NET Core framework, with no GraphQL package or runtime reference. The application calls `MapOperation` only when its validated composition plan enables API. No registration scanning, host construction, business factory or background task is performed by this library.

`OperationBinding<TRequest,TResponse>` provides a server-selected operation ID and pure typed validation shared with the GraphQL adapter. The host supplies `ITransportOperationDispatcher` in request services. For protected operations that bridge must use established protocol authentication and fresh identity/membership/resource/policy checks through `TenantOperationDispatcher`. An authenticated `ClaimsPrincipal`, caller headers, request tenant selection and Core correlation metadata do not independently establish tenant authority. Register authentication/authorization services and the authentication then authorization middleware; mapped endpoints require authorization and the execution method checks authentication again. No bearer parser, identity source or business operation is silently supplied.

Requests require POST, `application/json` with optional UTF-8 charset, no content encoding, and an object body of at most16384actual bytes. The reader counts streamed bytes even without Content-Length. JSON has depth32, strict property names/types, required constructor parameters, unknown-member rejection, no comments/trailing commas, no duplicate properties, and valid decoded Unicode. Typed validation runs before resolving the dispatcher. Invalid input returns generic `validation.failed`; validator/provider exceptions return generic `internal.error`. Response values serialize before any body is written.

Success is HTTP200 and a typed JSON value. Intentional failures use ProblemDetails-compatible objects with top-level `code`: `access.denied`403 with fixed generic message; `validation.failed`400; `resource.not_found`404; `resource.conflict`409; `operation.capacity_exceeded`503 with a fixed generic message; `internal.error`500; other intentional business failures422. Business error messages other than denial must be safe for their audience, as required by Core. Protocol failures use401/405/413/415. Actual client cancellation propagates `RequestAborted` without writing an error payload; an unrelated `OperationCanceledException` is a safe server fault. GraphQL can preserve the same operation/error semantics while retaining its protocol's response/status rules.

These bounded contracts do not establish production authentication, reverse-proxy/body-decompression safety, AOT, transport/provider throughput, deployment or supported-Windows qualification. Host-level tenant, disabled-module and real-network behavior require separate consumer evidence.

`ExportJsonSchema<TContract>()` returns a detached BCL structural schema using a copy
of the actual adapter serializer policy. `ExportErrorJsonSchema()` derives the
actual problem-envelope payload shape. Neither method exposes mutable transport
options, runs a validator/handler or grants authority. Nullable successful response
roots remain allowed; request object-only rules must be applied by the export
wrapper. Structural schemas do not encode duplicate-name/Unicode/byte parsing,
all numeric parser bounds, arbitrary validators or tenant policy. The generated
Small API's offline contract exporter supplies that bounded wrapper and shared
typed route catalog; no HTTP schema/introspection endpoint is added here.
