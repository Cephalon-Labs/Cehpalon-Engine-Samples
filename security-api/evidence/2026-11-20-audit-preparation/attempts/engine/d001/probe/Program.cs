using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;
var fixture=new Fixture();var factories=0;var store=new Store();
var recorder=TenantChangeAuditRecorder.Activate(new(TenantChangeAuditMode.MetadataOnly),()=>{factories++;return store;})!;
var registry=new TenantOperationRegistryBuilder().Register<string,bool>("document.update","write","document",x=>x,x=>new(new("A"),x),()=>new Handler(async context=>
{fixture.Mutations++;try{await recorder.RecordAsync(context,new(Guid.NewGuid(),context.Identity.Principal,context.Identity.AuthenticationScheme,context.Tenant,context.OperationId,context.Action,context.Resource.Kind,context.Resource.ResourceId,context.Resource.Version,TenantChangeKind.Update,"v1","v2"));}catch(TenantChangeAuditWriteException error){fixture.MayHaveCommitted=error.MayHaveCommitted;}})).Build();
var services=new TenantSecurityServices(fixture,new(["issuer"],["Bearer"]),fixture,fixture,TimeSpan.FromMinutes(1),fixture);
var result=await new TenantOperationDispatcher(registry,services).DispatchAsync<string,bool>("document.update","entity-1",new("probe"));
var valid=result.IsSuccess&&factories==1&&fixture.Mutations==1&&store.Records==0&&fixture.MayHaveCommitted;
Console.WriteLine(JsonSerializer.Serialize(new{baseline_revision="c3414287002070bc59477b62469baa03753769a4",sink_factories=factories,mutations=fixture.Mutations,records=store.Records,may_have_committed=fixture.MayHaveCommitted,observed_expected_old_behavior=valid}));
return valid?0:1;
sealed class Handler(Func<TenantOperationContext,Task> run):ITenantOperationHandler<string,bool>{public async ValueTask<OperationResult<bool>> HandleAsync(string request,TenantOperationContext context,CancellationToken token){await run(context);return OperationResult<bool>.Success(true);}}
sealed class Store:ITenantChangeAuditSink{public int Records;public ValueTask AppendAsync(TenantChangeAuditRecord record,CancellationToken token){Records++;return ValueTask.CompletedTask;}}
sealed class Fixture:IIdentitySource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy
{public int Mutations;public bool MayHaveCommitted;
public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken t)=>ValueTask.FromResult<IdentitySnapshot?>(new(new("issuer","alice"),"Bearer",DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddMinutes(5)));
public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot i,TenantId tenant,CancellationToken t)=>ValueTask.FromResult<TenantMembershipSnapshot?>(new(i.Principal,tenant,true,DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddMinutes(5),"m1"));
public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken t)=>ValueTask.FromResult<ResourceScopeSnapshot?>(new(tenant,kind,id,"acl1"));
public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken t)=>ValueTask.FromResult(true);}
