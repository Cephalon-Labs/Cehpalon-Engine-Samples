using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;

namespace Cehpalon.Engine.CodeGeneration;

/// <summary>Build-time typed registration only; generated calls do not instantiate handlers.</summary>
[Generator(LanguageNames.CSharp)]
public sealed class OperationRegistryGenerator : IIncrementalGenerator
{
    private const string AttributeName = "Cehpalon.Engine.Core.OperationAttribute";
    private const string HandlerName = "Cehpalon.Engine.Core.IOperationHandler`2";
    private const string GeneratedName = "Cehpalon.Engine.Generated.OperationRegistrations";
    private static readonly SymbolDisplayFormat TypeDisplay = SymbolDisplayFormat.FullyQualifiedFormat.WithMiscellaneousOptions(
        SymbolDisplayMiscellaneousOptions.EscapeKeywordIdentifiers |
        SymbolDisplayMiscellaneousOptions.IncludeNullableReferenceTypeModifier |
        SymbolDisplayMiscellaneousOptions.UseSpecialTypes);
    private static readonly DiagnosticDescriptor InvalidId = Rule("CEHGEN001", "Invalid operation ID", "Operation ID must match [a-z][a-z0-9_.-]{{0,127}}; received '{0}'");
    private static readonly DiagnosticDescriptor InvalidHandler = Rule("CEHGEN002", "Unsupported operation handler", "Handler '{0}' must be a concrete non-static, non-generic class with no generic containing type");
    private static readonly DiagnosticDescriptor Inaccessible = Rule("CEHGEN003", "Type cannot be named by generated registration", "Type '{0}' must be accessible from an assembly-level generated class and cannot be file-local");
    private static readonly DiagnosticDescriptor InvalidContract = Rule("CEHGEN004", "Ambiguous operation contract", "Handler '{0}' must implement exactly one distinct Cehpalon.Engine.Core.IOperationHandler<TRequest,TResponse> contract");
    private static readonly DiagnosticDescriptor DuplicateId = Rule("CEHGEN005", "Duplicate operation ID", "Operation ID '{0}' is declared by more than one handler");
    private static readonly DiagnosticDescriptor ReservedName = Rule("CEHGEN006", "Generated registry name is reserved", "Name 'Cehpalon.Engine.Generated.OperationRegistrations' and its containing namespace path are reserved for generated registration");
    private static readonly DiagnosticDescriptor DuplicateAttribute = Rule("CEHGEN007", "Duplicate operation attribute", "Handler '{0}' has multiple operation attributes");

    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        var candidates = context.SyntaxProvider.ForAttributeWithMetadataName(
            AttributeName,
            static (_, _) => true,
            static (attributeContext, token) => Analyze(attributeContext, token))
            .WithTrackingName("OperationCandidates");
        var reserved = context.CompilationProvider.Select(static (compilation, _) => HasReservedName(compilation));
        context.RegisterSourceOutput(candidates.Collect().Combine(reserved), static (production, input) =>
            Emit(production, input.Left, input.Right));
    }

    private static Candidate Analyze(GeneratorAttributeSyntaxContext context, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var symbol = context.TargetSymbol as INamedTypeSymbol;
        var location = context.TargetNode.GetLocation();
        if (symbol is null)
            return new Candidate(context.TargetSymbol, string.Empty, string.Empty, string.Empty, string.Empty, location,
                ImmutableArray.Create(Diagnostic.Create(InvalidHandler, location, context.TargetSymbol.Name)));

        var errors = ImmutableArray.CreateBuilder<Diagnostic>();
        var name = TypeName(symbol);
        var attribute = context.Attributes[0];
        // A syntax context contains attributes for its declaration. A partial
        // class can put another annotation on another declaration of this symbol.
        var operationAttributeCount = 0;
        foreach (var candidateAttribute in symbol.GetAttributes())
            if (SymbolEqualityComparer.Default.Equals(candidateAttribute.AttributeClass, attribute.AttributeClass))
                operationAttributeCount++;
        var id = attribute.ConstructorArguments.Length == 1 ? attribute.ConstructorArguments[0].Value as string : null;
        if (!ValidId(id)) errors.Add(Diagnostic.Create(InvalidId, location, id ?? "<null>"));
        if (operationAttributeCount != 1) errors.Add(Diagnostic.Create(DuplicateAttribute, location, name));
        if (symbol.TypeKind != TypeKind.Class || symbol.IsAbstract || symbol.IsStatic || HasGenericContainer(symbol))
            errors.Add(Diagnostic.Create(InvalidHandler, location, name));
        if (!CanName(symbol, context.SemanticModel.Compilation, token))
            errors.Add(Diagnostic.Create(Inaccessible, location, name));

        var definition = context.SemanticModel.Compilation.GetTypeByMetadataName(HandlerName);
        INamedTypeSymbol? contract = null;
        var contractCount = 0;
        if (definition is not null)
            foreach (var candidateContract in symbol.AllInterfaces)
                if (SymbolEqualityComparer.Default.Equals(candidateContract.OriginalDefinition, definition))
                {
                    contract = candidateContract;
                    contractCount++;
                }
        string request = string.Empty, response = string.Empty;
        if (contractCount != 1)
            errors.Add(Diagnostic.Create(InvalidContract, location, name));
        else
        {
            request = TypeName(contract!.TypeArguments[0]);
            response = TypeName(contract.TypeArguments[1]);
            foreach (var type in contract.TypeArguments)
                if (!CanName(type, context.SemanticModel.Compilation, token))
                    errors.Add(Diagnostic.Create(Inaccessible, location, TypeName(type)));
        }
        return new Candidate(symbol, id ?? string.Empty, name, request, response, location, errors.ToImmutable());
    }

    private static bool HasReservedName(Compilation compilation)
    {
        var current = compilation.Assembly.GlobalNamespace;
        foreach (var segment in new[] { "Cehpalon", "Engine", "Generated" })
        {
            var members = current.GetMembers(segment);
            if (members.Any(member => member is INamedTypeSymbol)) return true;
            current = members.OfType<INamespaceSymbol>().SingleOrDefault();
            if (current is null) return false;
        }
        return current.GetMembers("OperationRegistrations").Any(member =>
            member is INamespaceSymbol || member is INamedTypeSymbol named && named.Arity == 0);
    }

    private static bool HasGenericContainer(INamedTypeSymbol type)
    {
        for (var current = type; current is not null; current = current.ContainingType)
            if (current.Arity != 0) return true;
        return false;
    }

    private static bool CanName(ITypeSymbol type, Compilation compilation, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (type is IArrayTypeSymbol array) return CanName(array.ElementType, compilation, token);
        if (type is IDynamicTypeSymbol) return true;
        if (type is not INamedTypeSymbol named) return false;
        if (named.IsUnboundGenericType || named.TypeKind == TypeKind.Error) return false;
        for (var current = named; current is not null; current = current.ContainingType)
            if (current.IsFileLocal || !compilation.IsSymbolAccessibleWithin(current, compilation.Assembly)) return false;
        foreach (var argument in named.TypeArguments)
            if (!CanName(argument, compilation, token)) return false;
        return true;
    }

    private static string TypeName(ITypeSymbol type) => type.ToDisplayString(TypeDisplay);

    private static bool ValidId(string? id)
    {
        if (id is null || id.Length == 0 || id.Length > 128 || id[0] < 'a' || id[0] > 'z') return false;
        for (var i = 1; i < id.Length; i++)
        {
            var c = id[i];
            if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '_' && c != '.' && c != '-') return false;
        }
        return true;
    }

    private static void Emit(SourceProductionContext context, ImmutableArray<Candidate> candidates, bool reserved)
    {
        context.CancellationToken.ThrowIfCancellationRequested();
        if (candidates.Length == 0) return;
        var ordered = candidates.OrderBy(c => c.Id, StringComparer.Ordinal)
            .ThenBy(c => c.Handler, StringComparer.Ordinal)
            .ThenBy(c => c.Location.SourceTree?.FilePath, StringComparer.Ordinal)
            .ThenBy(c => c.Location.SourceSpan.Start).ToArray();
        var invalid = false;
        // Check every declaration before de-duplication. Display text is not a
        // semantic identity: distinct file-local types can share that text.
        foreach (var candidate in ordered)
            foreach (var diagnostic in candidate.Errors)
            {
                context.ReportDiagnostic(diagnostic);
                invalid = true;
            }
        // A partial symbol owns one registration; distinct symbols never merge
        // merely because their display names happen to be identical.
        var symbols = new HashSet<ISymbol>(SymbolEqualityComparer.Default);
        var distinct = new List<Candidate>(ordered.Length);
        var idCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var candidate in ordered)
            if (symbols.Add(candidate.Symbol))
            {
                distinct.Add(candidate);
                idCounts.TryGetValue(candidate.Id, out var count);
                idCounts[candidate.Id] = count + 1;
            }
        foreach (var candidate in distinct)
            if (idCounts[candidate.Id] > 1)
            {
                context.ReportDiagnostic(Diagnostic.Create(DuplicateId, candidate.Location, candidate.Id));
                invalid = true;
            }
        if (reserved)
        {
            context.ReportDiagnostic(Diagnostic.Create(ReservedName, distinct[0].Location));
            invalid = true;
        }
        if (invalid) return; // No partial registry: all annotated operations must be valid.

        var source = new StringBuilder("// <auto-generated/>\n#nullable enable\nnamespace Cehpalon.Engine.Generated\n{\n    internal static class OperationRegistrations\n    {\n        internal static void RegisterAll(global::Cehpalon.Engine.Core.OperationRegistryBuilder builder, global::Cehpalon.Engine.Core.IOperationHandlerFactory factory)\n        {\n            if (builder is null) throw new global::System.ArgumentNullException(nameof(builder));\n            if (factory is null) throw new global::System.ArgumentNullException(nameof(factory));\n");
        foreach (var candidate in distinct)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            source.Append("            builder.Register<").Append(candidate.Request).Append(", ").Append(candidate.Response)
                .Append(">(").Append(SymbolDisplay.FormatLiteral(candidate.Id, true))
                .Append(", () => factory.Create<").Append(candidate.Handler).Append(">());\n");
        }
        source.Append("        }\n    }\n}\n");
        context.AddSource("OperationRegistrations.g.cs", SourceText.From(source.ToString(), Encoding.UTF8));
    }

    private static DiagnosticDescriptor Rule(string id, string title, string message) =>
        new DiagnosticDescriptor(id, title, message, "Cehpalon.CodeGeneration", DiagnosticSeverity.Error, true);

    private sealed class Candidate
    {
        public Candidate(ISymbol symbol, string id, string handler, string request, string response, Location location, ImmutableArray<Diagnostic> errors)
        {
            Symbol = symbol; Id = id; Handler = handler; Request = request; Response = response; Location = location; Errors = errors;
        }
        public ISymbol Symbol { get; }
        public string Id { get; }
        public string Handler { get; }
        public string Request { get; }
        public string Response { get; }
        public Location Location { get; }
        public ImmutableArray<Diagnostic> Errors { get; }
    }
}
