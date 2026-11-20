using System.Text.RegularExpressions;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Transports.Http;
using HotChocolate;
using HotChocolate.Resolvers;
using HotChocolate.Types;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Cehpalon.Engine.Transports.GraphQL;

/// <summary>Explicit, immutable operation fields. Construction does not register services or build a schema.</summary>
public sealed class GraphQLOperationCatalog
{
    private readonly Field[] _fields;
    private GraphQLOperationCatalog(Field[] fields) => _fields = fields;

    public sealed class Builder
    {
        private readonly List<Field> _fields = [];

        public Builder AddQuery<TRequest,TResponse>(string fieldName, OperationBinding<TRequest,TResponse> binding)
            where TRequest : class where TResponse : class => Add(fieldName, binding, false);

        public Builder AddMutation<TRequest,TResponse>(string fieldName, OperationBinding<TRequest,TResponse> binding)
            where TRequest : class where TResponse : class => Add(fieldName, binding, true);

        private Builder Add<TRequest,TResponse>(string name, OperationBinding<TRequest,TResponse> binding, bool mutation)
            where TRequest : class where TResponse : class
        {
            ArgumentNullException.ThrowIfNull(binding);
            if (name is null || name.Length > 128 || !Regex.IsMatch(name, "^[A-Za-z][A-Za-z0-9_]*$", RegexOptions.CultureInvariant) || name.StartsWith("__", StringComparison.Ordinal))
                throw new ArgumentException("Use a GraphQL field name with at most 128 ASCII characters.", nameof(name));
            if (_fields.Any(field => field.Mutation == mutation && field.Name == name))
                throw new ArgumentException("Duplicate GraphQL field.", nameof(name));
            if (_fields.Count >= 256) throw new ArgumentException("At most 256 GraphQL operation fields are supported.");
            _fields.Add(new TypedField<TRequest,TResponse>(name, mutation, binding));
            return this;
        }

        public GraphQLOperationCatalog Build()
        {
            if (!_fields.Any(field => !field.Mutation)) throw new InvalidOperationException("At least one query field is required.");
            return new(_fields.ToArray());
        }
    }

    internal ObjectType QueryType() => new(descriptor =>
    {
        descriptor.Name("Query");
        foreach (var field in _fields.Where(field => !field.Mutation)) field.Configure(descriptor);
    });

    internal ObjectType? MutationType() => !_fields.Any(field => field.Mutation) ? null : new(descriptor =>
    {
        descriptor.Name("Mutation");
        foreach (var field in _fields.Where(field => field.Mutation)) field.Configure(descriptor);
    });

    private abstract record Field(string Name, bool Mutation)
    {
        public abstract void Configure(IObjectTypeDescriptor descriptor);
    }

    private sealed record TypedField<TRequest,TResponse>(string FieldName, bool IsMutation, OperationBinding<TRequest,TResponse> Binding)
        : Field(FieldName, IsMutation) where TRequest : class where TResponse : class
    {
        public override void Configure(IObjectTypeDescriptor descriptor) => descriptor.Field(Name)
            .Argument("input", argument => argument.Type<NonNullType<InputObjectType<TRequest>>>())
            .Type<ObjectType<TResponse>>()
            .Resolve(context => Resolve(context));

        private async ValueTask<object?> Resolve(IResolverContext context)
        {
            // The endpoint guards authentication; check again before dispatch so alternate executor wiring fails closed.
            var http = context.Service<IHttpContextAccessor>().HttpContext;
            if (http is null || !http.User.Identities.Any(identity => identity.IsAuthenticated))
                throw Error(TransportErrors.AccessDenied());
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(http.RequestAborted, context.RequestAborted);
            OperationResult<TResponse> result;
            try
            {
                cancellation.Token.ThrowIfCancellationRequested();
                var request = context.ArgumentValue<TRequest>("input");
                if (request is null || Binding.Validate(request) is not null)
                    result = OperationResult<TResponse>.Failure(TransportErrors.ValidationFailed());
                else
                {
                    var dispatcher = http.RequestServices.GetRequiredService<ITransportOperationDispatcher>();
                    result = await dispatcher.DispatchAsync<TRequest,TResponse>(http, Binding.OperationId, request,
                        new Cehpalon.Engine.Core.OperationContext(http.TraceIdentifier), cancellation.Token).ConfigureAwait(false);
                }
                cancellation.Token.ThrowIfCancellationRequested();
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { throw; }
            catch { throw Error(TransportErrors.InternalError()); }
            // Only adapter-created protocol errors are emitted; exceptions from host components are always sanitized.
            return result.IsSuccess ? result.Value : throw Error(TransportErrors.ForClient(result.Error));
        }

        private static GraphQLException Error(OperationError error) => new(ErrorBuilder.New()
            .SetCode(error.Code).SetMessage(error.Message).Build());
    }
}
