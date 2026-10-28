"""Owned synthetic TLS fault tests. These are robustness tests, never capacity observations."""
import collections, gzip, hashlib, http.server, json, os, pathlib, socket, ssl, subprocess, threading, time

BASE=pathlib.Path(__file__).resolve().parent
RUN=BASE/'collector-robustness-01'
RUN.mkdir(exist_ok=False)
SDK='/home/tom/.local/share/cehpalon-benchmark-deployment/tuning-20261028/sdk/dotnet'
DLL='/mnt/d/Cephalon/.worktrees/w2-collector-readiness/.local/readiness-build01/artifacts/bin/SmallApi.Benchmark/release/SmallApi.Benchmark.dll'
PRIVATE=pathlib.Path('/home/tom/.local/share/cehpalon-benchmark-private/collector-robustness-01')
PRIVATE.parent.mkdir(parents=True,exist_ok=True)
subprocess.run([SDK,DLL,'--create-fixture='+str(PRIVATE)],check=True,capture_output=True)
os.chmod(PRIVATE,0o700)
for flag,name in [('-clcerts','server.pem'),('-nocerts','key.pem')]:
    subprocess.run(['openssl','pkcs12','-in',str(PRIVATE/'server.pfx'),'-passin','pass:','-nodes',flag,'-out',str(PRIVATE/name)],check=True,capture_output=True)
    os.chmod(PRIVATE/name,0o600)

def item(i): return dict(id=i,label=f'item-{i:05}',revision=0,amountMinorUnits=i*17)
class Server(http.server.ThreadingHTTPServer):
    daemon_threads=True
    request_queue_size=256
    def __init__(self,mode):
        self.mode=mode; self.reads=0; self.lock=threading.Lock(); self.stop=threading.Event(); self.sockets=set(); self.active=0; self.maxactive=0
        super().__init__(('127.0.0.1',0),Handler)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(PRIVATE/'server.pem',PRIVATE/'key.pem')
        self.socket=ctx.wrap_socket(self.socket,server_side=True)
    def get_request(self):
        conn,addr=super().get_request()
        with self.lock:self.sockets.add(conn)
        return conn,addr
    def process_request_thread(self,request,address):
        with self.lock:self.active+=1;self.maxactive=max(self.maxactive,self.active)
        try:super().process_request_thread(request,address)
        finally:
            with self.lock:self.active-=1;self.sockets.discard(request)
    def finish(self):
        self.stop.set();self.shutdown()
        with self.lock:sockets=list(self.sockets)
        for conn in sockets:
            try:conn.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            conn.close()
        self.server_close()
        deadline=time.monotonic()+5
        while self.active and time.monotonic()<deadline:time.sleep(.01)

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def handle(self):
        try:super().handle()
        except (OSError,ssl.SSLError):pass
    def reply(self,value,status=200,close=False,empty=False):
        data=b'' if empty else json.dumps(value,separators=(',',':')).encode()
        self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)))
        if close:self.send_header('Connection','close');self.close_connection=True
        self.end_headers();self.wfile.write(data);self.wfile.flush()
    def do_GET(self):
        if self.path=='/__fixture/state':self.reply({'records':[item(i) for i in range(1,10001)]})
        else:self.reply({})
    def do_POST(self):
        raw=self.rfile.read(int(self.headers.get('Content-Length','0')))
        if self.path=='/__fixture/reset':self.reply({});return
        body=json.loads(raw)
        with self.server.lock:self.server.reads+=1;n=self.server.reads
        mode=self.server.mode
        if mode=='header-timeout' and n==3:self.server.stop.wait(45);return
        if mode=='phase-503' and n>130:self.reply({'fault':'synthetic-after-preparation'},503);return
        op=self.path.rsplit('/',1)[-1]
        value={'items':[item(1+body['page']*20+i) for i in range(20)]} if op=='list' else item(body['id'])
        if mode=='invalid-body' and n==3:value['label']='deliberately-invalid'
        self.reply(value,close=mode=='connection-close' and n==3,empty=mode=='empty-body' and n==3)

summaries=[]
for mode in ['connection-close','empty-body','invalid-body','header-timeout','phase-503']:
    directory=RUN/mode;directory.mkdir()
    server=Server(mode);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    command=[SDK,DLL,'--load-client','--url=https://127.0.0.1:'+str(server.server_port),'--ca-file='+str(PRIVATE/'root-ca.der'),'--transport=http','--output='+str(directory),'--rate=2000','--seconds=1','--warmup=1']
    start=time.monotonic()
    with (directory/'stdout.txt').open('wb') as out,(directory/'stderr.txt').open('wb') as err:
        process=subprocess.Popen(command,stdout=out,stderr=err)
        try:exitcode=process.wait(timeout=45)
        except subprocess.TimeoutExpired:process.kill();process.wait();exitcode='harness-timeout'
    elapsed=time.monotonic()-start
    server.finish();thread.join(5)
    checks={};detail={}
    try:
        prep=json.loads((directory/'collector-preparation.json').read_text());failure=json.loads((directory/'collector-failure.json').read_text())
        checks['nonzero_managed_exit']=exitcode==1
        checks['joined_all_started_preparation_rows']=len(prep['requests'])==prep['readOnlyRequests'] and all(r['completedTicks'] is not None for r in prep['requests'])
        checks['retained_tls_and_client']=bool(prep['tlsConnections']) and all(k in prep for k in ['clientBefore','clientAfter']) and bool(failure['tlsConnections']) and 'client' in failure
        checks['no_later_phase_artifacts']=not any((directory/name).exists() for name in ['warmup-requests.jsonl.gz','measured-requests.jsonl.gz','load-result.json','warmup-result.json'])
        checks['no_later_phase_flags']=failure['warmupEntered'] is False and failure['measuredEntered'] is False
        checks['bounded_exit']=elapsed<40
        checks['fixture_workers_joined']=server.active==0
        if mode!='phase-503':
            checks['preparation_rejected']=prep['status']=='preparation-failed' and failure['stage']=='preparation' and failure['enteredPhases']==[]
            checks['no_phase_evidence']=not (directory/'preflight-requests.jsonl.gz').exists()
            if mode=='header-timeout':
                prep_seconds=(prep['preparationCompletedTicks']-prep['preparationStartedTicks'])/prep['stopwatchFrequency']
                checks['one_shared_30s_deadline']=29<=prep_seconds<35
                detail['preparationSeconds']=prep_seconds
        else:
            accounting=json.loads((directory/'preflight-evidence-accounting.json').read_text());report=json.loads((directory/'collector-preflight.json').read_text())
            with gzip.open(directory/'preflight-requests.jsonl.gz','rt') as file:header=json.loads(next(file));rows=[json.loads(line) for line in file]
            errors=collections.Counter(row[7] for row in rows if row[7])
            checks['128_distinct_live_preparation_connections']=prep['status']=='passed' and prep['barrier']['passed'] and prep['barrier']['distinctConnectionCount']==128 and prep['barrier']['tlsConnectionsAtBarrier']==128
            checks['all_4000_raw_rows_retained']=len(rows)==4000 and [r[0] for r in rows]==list(range(4000)) and accounting['observedCount']==4000
            checks['failed_preflight_count_conservation']=report['preflight']['errors']==sum(errors.values())==4000 and report['preflight']['correct']==0 and report['status']=='collector-preflight-failed'
            checks['structured_phase_coherence']=failure['status']=='collector-preflight-failed' and failure['stage']=='preflight' and failure['enteredPhases']==['preflight'] and failure['counts']==report['preflight']
            checks['phase_tls_retained']=bool(accounting['tlsConnectionsBefore']) and bool(accounting['tlsConnectionsAfter']) and 'newTlsConnectionIds' in accounting
            detail.update(errorKinds=errors,phaseTlsBefore=len(accounting['tlsConnectionsBefore']),phaseTlsAfter=len(accounting['tlsConnectionsAfter']))
        detail.update(preparationRows=prep['readOnlyRequests'],preparationSuccessful=prep['successfulReadOnlyRequests'],tlsConnections=len(prep['tlsConnections']),status=failure['status'])
    except Exception as error:checks['evidence_readable']=False;detail['auditError']=repr(error)
    result=dict(case=mode,exitCode=exitcode,elapsedSeconds=elapsed,passed=all(checks.values()),checks=checks,detail=detail,fixtureCatalogRequests=server.reads,fixturePeakWorkers=server.maxactive)
    (directory/'robustness-audit.json').write_text(json.dumps(result,indent=2)+'\n');summaries.append(result);print(json.dumps(result),flush=True)
files=[]
for path in sorted(RUN.rglob('*')):
    if path.is_file():files.append(dict(path=str(path.relative_to(RUN)),bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
summary=dict(scope='Synthetic owned TLS robustness tests; not a capacity or benchmark run',driverDllSha256=hashlib.sha256(pathlib.Path(DLL).read_bytes()).hexdigest(),scriptSha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),cases=summaries,passed=all(row['passed'] for row in summaries),files=files,privateFixtureExcluded=True)
(RUN/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print('FINAL',summary['passed'],flush=True)
