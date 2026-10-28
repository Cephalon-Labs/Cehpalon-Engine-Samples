using System.Text.Json;
using System.Text.Json.Serialization;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Transports.Http;
using HotChocolate;
using HotChocolate.Resolvers;
using HotChocolate.Types;
using Microsoft.Net.Http.Headers;

namespace SmallApi.Benchmark;

// Native baseline codec intentionally independent of Engine adapter execution.
// Settings, limits and declared semantics are held equal by the conformance corpus.
public static class Wire
{
    public const int MaximumBytes=16384;
    public static readonly JsonSerializerOptions Json=new(JsonSerializerDefaults.Web){PropertyNameCaseInsensitive=false,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,NumberHandling=JsonNumberHandling.Strict,RespectNullableAnnotations=true,RespectRequiredConstructorParameters=true,MaxDepth=32,IncludeFields=true};
    public static int Status(string code)=>code switch{"access.denied"=>403,"validation.failed"=>400,"resource.not_found"=>404,"resource.conflict"=>409,"internal.error"=>500,_=>422};
    public static async Task Error(HttpContext http,int status,string code,string message)
    {
        http.Response.StatusCode=status;http.Response.ContentType="application/problem+json; charset=utf-8";
        var payload=JsonSerializer.SerializeToUtf8Bytes(new{type="about:blank",title=message,status,code});await http.Response.Body.WriteAsync(payload,http.RequestAborted);
    }
    private static bool HttpContent(HttpRequest request)
    {
        if(!MediaTypeHeaderValue.TryParse(request.ContentType,out var media) || !media.MediaType.Equals("application/json",StringComparison.OrdinalIgnoreCase))return false;
        var charset=media.Charset.Value;return (string.IsNullOrEmpty(charset)||charset.Equals("utf-8",StringComparison.OrdinalIgnoreCase))&&request.Headers.ContentEncoding.Count==0;
    }
    public static async Task<byte[]?> Read(HttpContext http,bool graphql=false)
    {
        async Task Reject(int status,string code,string message){if(graphql)http.Response.StatusCode=status;else await Error(http,status,code,message);}
        if(!(graphql?http.Request.HasJsonContentType():HttpContent(http.Request))){await Reject(415,"request.content_type","UTF-8 JSON is required.");return null;}
        if(http.Request.ContentLength>MaximumBytes){await Reject(413,"request.too_large","Request body exceeds 16384 bytes.");return null;}
        var bytes=new byte[MaximumBytes+1];var length=0;
        while(length<bytes.Length){var n=await http.Request.Body.ReadAsync(bytes.AsMemory(length),http.RequestAborted);if(n==0)break;length+=n;}
        if(length>MaximumBytes){await Reject(413,"request.too_large","Request body exceeds 16384 bytes.");return null;}
        return bytes[..length];
    }
    public static bool Structural(JsonElement element)
    {
        if(element.ValueKind==JsonValueKind.Object){var names=new HashSet<string>(StringComparer.Ordinal);foreach(var p in element.EnumerateObject())if(!names.Add(p.Name)||!ValidUnicode(p.Name)||!Structural(p.Value))return false;}
        else if(element.ValueKind==JsonValueKind.Array){foreach(var x in element.EnumerateArray())if(!Structural(x))return false;}
        else if(element.ValueKind==JsonValueKind.String && !ValidUnicode(element.GetString()!))return false;
        return true;
    }
    private static bool ValidUnicode(string text)
    {for(var i=0;i<text.Length;i++){if(char.IsLowSurrogate(text[i]))return false;if(char.IsHighSurrogate(text[i]) && (++i>=text.Length||!char.IsLowSurrogate(text[i])))return false;}return true;}
    public static void Map<TRequest,TResponse>(IEndpointRouteBuilder app,string path,OperationBinding<TRequest,TResponse> binding,Dispatch dispatch)
    {
        Func<HttpContext,Task> action=async http=>
        {
            try
            {
                var bytes=await Read(http);if(bytes is null)return;
                TRequest request;
                try{using var document=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=32});if(document.RootElement.ValueKind!=JsonValueKind.Object || !Structural(document.RootElement))throw new JsonException();request=document.RootElement.Deserialize<TRequest>(Json)??throw new JsonException();}
                catch(Exception e)when(e is JsonException or InvalidOperationException){await Error(http,400,"validation.failed","Request validation failed.");return;}
                if(binding.Validate(request)is not null){await Error(http,400,"validation.failed","Request validation failed.");return;}
                var ct=http.RequestAborted;ct.ThrowIfCancellationRequested();
                var result=await dispatch.DispatchAsync<TRequest,TResponse>(http,binding.OperationId,request,new(http.TraceIdentifier),ct);ct.ThrowIfCancellationRequested();
                if(result.IsSuccess){var body=JsonSerializer.SerializeToUtf8Bytes(result.Value,Json);http.Response.ContentType="application/json; charset=utf-8";await http.Response.Body.WriteAsync(body,ct);}
                else await Error(http,Status(result.Error.Code),result.Error.Code,result.Error.Message);
            }
            catch(OperationCanceledException)when(http.RequestAborted.IsCancellationRequested){throw;}
            catch{if(!http.Response.HasStarted)await Error(http,500,"internal.error","An internal error occurred.");}
        };
        app.MapPost(path,(Delegate)action).RequireAuthorization();
    }
    public static void QueryField<TRequest,TResponse>(IObjectTypeDescriptor descriptor,string name,OperationBinding<TRequest,TResponse> binding,Dispatch dispatch)where TRequest:class where TResponse:class
    {
        descriptor.Field(name).Argument("input",a=>a.Type<NonNullType<InputObjectType<TRequest>>>()).Type<ObjectType<TResponse>>().Resolve(context=>Resolve(context,binding,dispatch));
    }
    private static async ValueTask<object?> Resolve<TRequest,TResponse>(IResolverContext context,OperationBinding<TRequest,TResponse> binding,Dispatch dispatch)where TRequest:class where TResponse:class
    {
        var http=context.Service<IHttpContextAccessor>().HttpContext??throw new InvalidOperationException();
        using var cancel=CancellationTokenSource.CreateLinkedTokenSource(http.RequestAborted,context.RequestAborted);
        OperationResult<TResponse> result;
        try{cancel.Token.ThrowIfCancellationRequested();var input=context.ArgumentValue<TRequest>("input");result=input is null || binding.Validate(input)is not null?OperationResult<TResponse>.Failure(Bindings.Invalid()):await dispatch.DispatchAsync<TRequest,TResponse>(http,binding.OperationId,input,new(http.TraceIdentifier),cancel.Token);cancel.Token.ThrowIfCancellationRequested();}
        catch(OperationCanceledException)when(cancel.IsCancellationRequested){throw;}
        catch{throw new GraphQLException(ErrorBuilder.New().SetCode("internal.error").SetMessage("An internal error occurred.").Build());}
        return result.IsSuccess?result.Value:throw new GraphQLException(ErrorBuilder.New().SetCode(result.Error.Code).SetMessage(result.Error.Message).Build());
    }
    private static bool HasValidStringEncoding(ReadOnlySpan<byte> json)
    {
        var reader = new Utf8JsonReader(json, new JsonReaderOptions { MaxDepth = 32 });
        while (reader.Read())
        {
            if (reader.TokenType is not (JsonTokenType.String or JsonTokenType.PropertyName)) continue;
            if (!ValidUnicode(reader.GetString()!)) return false;
            // JsonDocument may replace an escaped lone surrogate in a property name. Inspect raw escapes as well.
            var text = reader.ValueSpan;
            for (var index = 0; index < text.Length; index++)
            {
                if (text[index] != '\\') continue;
                index++;
                if (text[index] != 'u') continue;
                var unit = HexUnit(text.Slice(index + 1, 4));
                index += 4;
                if (unit is >= 0xDC00 and <= 0xDFFF) return false;
                if (unit is < 0xD800 or > 0xDBFF) continue;
                if (index + 6 >= text.Length || text[index + 1] != '\\' || text[index + 2] != 'u') return false;
                var low = HexUnit(text.Slice(index + 3, 4));
                if (low is < 0xDC00 or > 0xDFFF) return false;
                index += 6;
            }
        }
        return true;
    }

    private static int HexUnit(ReadOnlySpan<byte> value)
    {
        var result = 0;
        foreach (var digit in value) result = result * 16 + (digit <= '9' ? digit - '0' : (digit | 32) - 'a' + 10);
        return result;
    }

    public static async Task GuardGraphQL(HttpContext http,RequestDelegate next)
    {
        if(!HttpMethods.IsPost(http.Request.Method)){http.Response.StatusCode=405;return;}
        var bytes=await Read(http,true);if(bytes is null)return;
        try
        {
            if(!HasValidStringEncoding(bytes))throw new JsonException();
            using var document=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=32});var root=document.RootElement;
            if(root.ValueKind!=JsonValueKind.Object || !Structural(root)||!root.TryGetProperty("query",out var query)||query.ValueKind!=JsonValueKind.String)throw new JsonException();
            foreach(var p in root.EnumerateObject())if(p.Name!="query" && !(p.Name=="variables" && p.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Null) && !(p.Name=="operationName" && p.Value.ValueKind is JsonValueKind.String or JsonValueKind.Null))throw new JsonException();
        }
        catch(Exception e)when(e is JsonException or InvalidOperationException){http.Response.StatusCode=400;return;}
        var original=http.Request.Body;await using var body=new MemoryStream(bytes);http.Request.Body=body;http.Request.ContentLength=bytes.Length;
        try{await next(http);}finally{http.Request.Body=original;}
    }
}
