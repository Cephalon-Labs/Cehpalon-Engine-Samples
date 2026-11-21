using System.Text;
using System.Text.Json;

namespace Cehpalon.Engine.Composition;

/// <summary>Pure, bounded startup compiler. No callbacks or runtime resources are accepted.</summary>
public static class CompositionCompiler
{
    public const int MaximumConfigurationBytes = 1_048_576;
    public const int MaximumModules = 256;
    public const int MaximumJsonDepth = 32;

    public static CompositionCompilation Compile(string appsettingsJson, IEnumerable<ModuleDescriptor> catalog)
    {
        ArgumentNullException.ThrowIfNull(appsettingsJson);
        ArgumentNullException.ThrowIfNull(catalog);
        var diagnostics = new List<CompositionDiagnostic>();
        void Error(string code, string path, string message) => diagnostics.Add(new(code, path, message));
        if (appsettingsJson.Length > MaximumConfigurationBytes || Encoding.UTF8.GetByteCount(appsettingsJson) > MaximumConfigurationBytes)
            return Failure("CFG_SIZE", "$", $"Configuration exceeds {MaximumConfigurationBytes} UTF-8 bytes.");

        // Enumeration is bounded even when an untrusted/custom enumerable never ends.
        var descriptors = catalog.Take(MaximumModules + 1).ToArray();
        if (descriptors.Length > MaximumModules)
            return Failure("CAT_SIZE", "$catalog", $"Catalog exceeds {MaximumModules} modules.");
        var modules = new SortedDictionary<string, ModuleDescriptor>(StringComparer.Ordinal);
        foreach (var module in descriptors)
        {
            if (module is null) { Error("CAT_NULL", "$catalog", "Catalog contains a null descriptor."); continue; }
            if (!ValidId(module.Id)) { Error("CAT_ID", "$catalog", "Module IDs must match [a-z][a-z0-9_.-]{0,127}."); continue; }
            if (!Enum.IsDefined(module.Role)) { Error("CAT_ROLE", "$catalog." + module.Id, "Unknown module role."); continue; }
            if (!modules.TryAdd(module.Id, module)) Error("CAT_DUPLICATE", "$catalog." + module.Id, "Duplicate module ID.");
            if (module.Dependencies.Count > MaximumModules) Error("CAT_DEPENDENCIES", "$catalog." + module.Id, "Too many dependencies.");
        }
        foreach (var module in modules.Values)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var dependency in module.Dependencies)
            {
                if (dependency is null || !ValidId(dependency)) Error("CAT_DEPENDENCY_ID", "$catalog." + module.Id, "Invalid dependency ID.");
                else if (!seen.Add(dependency)) Error("CAT_DEPENDENCY_DUPLICATE", "$catalog." + module.Id, "Duplicate dependency: " + dependency);
                else if (!modules.ContainsKey(dependency)) Error("CAT_MISSING", "$catalog." + module.Id, "Missing dependency: " + dependency);
            }
        }
        if (diagnostics.Count != 0) return Failed();

        // Validate every catalog component, even when all affected modules are disabled.
        var colors = new Dictionary<string, int>(StringComparer.Ordinal);
        bool CheckCycle(string id)
        {
            if (colors.TryGetValue(id, out var color)) return color == 1;
            colors[id] = 1;
            foreach (var dependency in modules[id].Dependencies.Order(StringComparer.Ordinal))
                if (CheckCycle(dependency)) return true;
            colors[id] = 2;
            return false;
        }
        foreach (var id in modules.Keys)
            if (CheckCycle(id)) { Error("CAT_CYCLE", "$catalog." + id, "Dependency cycle detected."); break; }
        if (diagnostics.Count != 0) return Failed();

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(appsettingsJson, new JsonDocumentOptions { MaxDepth = MaximumJsonDepth });
        }
        catch (JsonException)
        {
            // Avoid echoing raw configuration, exception excerpts or provider secrets.
            return Failure("CFG_JSON", "$", "Malformed JSON or maximum JSON depth exceeded.");
        }
        catch (ArgumentException)
        {
            // Parse(string) can reject malformed UTF-16 before producing a JSON exception.
            return Failure("CFG_JSON", "$", "Malformed JSON text encoding.");
        }
        using (document)
        {
            var root = document.RootElement;
            try { ValidateJsonStrings(root); }
            catch (InvalidOperationException)
            {
                // Escaped lone surrogates can pass Parse but fail later string access.
                return Failure("CFG_JSON", "$", "Malformed JSON text encoding.");
            }
            if (root.ValueKind != JsonValueKind.Object) return Failure("CFG_ROOT", "$", "Appsettings root must be an object.");
            if (!UniqueProperties(root, "$")) return Failed();
            if (!root.TryGetProperty("Cehpalon", out var section)) return Failure("CFG_SECTION", "$.Cehpalon", "Required Cehpalon section is missing or has incorrect casing.");
            if (!Object(section, "$.Cehpalon", ["SchemaVersion", "Architecture", "Topology", "Pattern", "Modules"])) return Failed();
            if (!section.TryGetProperty("SchemaVersion", out var version) || version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out var schema) || schema != 1)
                Error("CFG_VERSION", "$.Cehpalon.SchemaVersion", "SchemaVersion must be integer 1.");
            Literal("Architecture", "Modular"); Literal("Topology", "SingleProcess"); Literal("Pattern", "RequestReply");
            if (!section.TryGetProperty("Modules", out var selections) || selections.ValueKind != JsonValueKind.Object)
                Error("CFG_MODULES", "$.Cehpalon.Modules", "Modules must be an object.");
            if (diagnostics.Count != 0) return Failed();
            if (!UniqueProperties(selections, "$.Cehpalon.Modules")) return Failed();
            var requested = new Dictionary<string, bool>(StringComparer.Ordinal);
            var selectionCount = 0;
            foreach (var item in selections.EnumerateObject())
            {
                var path = "$.Cehpalon.Modules." + item.Name;
                if (++selectionCount > MaximumModules) { Error("CFG_MODULE_LIMIT", "$.Cehpalon.Modules", "Too many module selections."); break; }
                if (!modules.ContainsKey(item.Name)) { Error("CFG_UNKNOWN_MODULE", path, "Unknown or incorrectly cased module ID."); continue; }
                if (!Object(item.Value, path, ["Enabled"])) continue;
                if (!item.Value.TryGetProperty("Enabled", out var enabled) || enabled.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                    Error("CFG_ENABLED", path + ".Enabled", "Enabled must be a JSON boolean.");
                else requested[item.Name] = enabled.GetBoolean();
            }
            if (diagnostics.Count != 0) return Failed();

            var active = new HashSet<string>(StringComparer.Ordinal);
            var reasons = new Dictionary<string, string>(StringComparer.Ordinal);
            void Enable(string id, string parent)
            {
                if (requested.TryGetValue(id, out var enabled) && !enabled)
                { Error("PLAN_FORBIDDEN", "$.Cehpalon.Modules." + id, "Explicitly disabled module is required by " + parent + "."); return; }
                if (modules[id].Role == ModuleRole.EntryPoint && (!requested.TryGetValue(id, out var selected) || !selected))
                { Error("PLAN_ENTRYPOINT", "$.Cehpalon.Modules." + id, "Entrypoint dependency requires its own explicit Enabled:true selection."); return; }
                if (!active.Add(id)) return;
                reasons[id] = requested.TryGetValue(id, out var explicitlyEnabled) && explicitlyEnabled ? "explicit Enabled:true" : "support dependency of " + parent;
                foreach (var dependency in modules[id].Dependencies.Order(StringComparer.Ordinal)) Enable(dependency, id);
            }
            foreach (var item in requested.Where(p => p.Value).OrderBy(p => p.Key, StringComparer.Ordinal)) Enable(item.Key, "explicit root");
            if (diagnostics.Count != 0) return Failed();

            // Kahn's algorithm chooses the lexically smallest ready module at every step.
            var remaining = active.ToDictionary(id => id, id => modules[id].Dependencies.Count(active.Contains), StringComparer.Ordinal);
            var ready = new SortedSet<string>(remaining.Where(p => p.Value == 0).Select(p => p.Key), StringComparer.Ordinal);
            var order = new List<string>();
            while (ready.Count != 0)
            {
                var id = ready.Min!; ready.Remove(id); order.Add(id);
                foreach (var dependent in active.Order(StringComparer.Ordinal))
                    if (modules[dependent].Dependencies.Contains(id, StringComparer.Ordinal) && --remaining[dependent] == 0) ready.Add(dependent);
            }
            var decisions = modules.Values.Select(m => new ModuleDecision(m.Id, m.Role, active.Contains(m.Id),
                active.Contains(m.Id) ? reasons[m.Id] : requested.TryGetValue(m.Id, out var selected) && !selected ? "explicit Enabled:false" : "not selected or required"));
            return new(new ActivationPlan(order, decisions), []);

            void Literal(string name, string expected)
            {
                if (!section.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String || value.GetString() != expected)
                    Error("CFG_PROFILE", "$.Cehpalon." + name, "Only " + expected + " is supported in schema 1.");
            }
        }

        bool UniqueProperties(JsonElement obj, string path)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in obj.EnumerateObject())
                if (!seen.Add(property.Name)) Error("CFG_DUPLICATE", path, "Duplicate or case-ambiguous property name.");
            return diagnostics.Count == 0;
        }
        bool Object(JsonElement obj, string path, string[] allowed)
        {
            if (obj.ValueKind != JsonValueKind.Object) { Error("CFG_OBJECT", path, "Expected object."); return false; }
            if (!UniqueProperties(obj, path)) return false;
            foreach (var property in obj.EnumerateObject())
                if (!allowed.Contains(property.Name, StringComparer.Ordinal)) Error("CFG_UNKNOWN", path, "Unknown or incorrectly cased property.");
            return diagnostics.Count == 0;
        }
        CompositionCompilation Failed() => new(null, diagnostics);
    }

    private static CompositionCompilation Failure(string code, string path, string message) => new(null, [new(code, path, message)]);
    private static void ValidateJsonStrings(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.String) _ = value.GetString();
        else if (value.ValueKind == JsonValueKind.Object)
            foreach (var property in value.EnumerateObject())
            {
                _ = property.Name;
                ValidateJsonStrings(property.Value);
            }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) ValidateJsonStrings(item);
    }
    private static bool ValidId(string value) => value.Length is >= 1 and <= 128 && value[0] is >= 'a' and <= 'z'
        && value.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '.' or '-');
}
