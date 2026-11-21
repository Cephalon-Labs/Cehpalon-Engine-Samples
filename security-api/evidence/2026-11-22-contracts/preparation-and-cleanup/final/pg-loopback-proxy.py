import os,socket,subprocess,threading,json,time
from pathlib import Path
root=Path(__file__).resolve().parent;stop=root/'pg-proxy.stop'
assert not stop.exists(),'Retain old control file; choose a new attempt'
gate=threading.Lock();children=set();active=set();accepted=0
def relay(client):
 process=None
 try:
  process=subprocess.Popen(['wsl','-d','Ubuntu','--','python3','-u','/mnt/d/Cephalon/.worktrees/ahx-consumer/.local/fixture03/pg-stdio-bridge.py'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
  with gate:children.add(process);active.add(client)
  def upload():
   try:
    while True:
     data=client.recv(65536)
     if not data:break
     process.stdin.write(data);process.stdin.flush()
   except (OSError,ValueError):pass
   finally:
    try:process.stdin.close()
    except OSError:pass
  threading.Thread(target=upload,daemon=True).start()
  while True:
   data=os.read(process.stdout.fileno(),65536)
   if not data:break
   client.sendall(data)
 except (OSError,ValueError):pass
 finally:
  client.close()
  if process is not None:
   try:process.wait(timeout=2)
   except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=5)
   with gate:children.discard(process);active.discard(client)
server=socket.socket();server.bind(('127.0.0.1',0));server.listen(64);server.settimeout(.5)
(root/'pg-proxy-owned-process.json').write_text(json.dumps({'pid':os.getpid(),'bind':'127.0.0.1:'+str(server.getsockname()[1]),'upstream':'WSL binary stdio to WSL127.0.0.1:55438','logs_protocol_bytes':False})+'\n')
(root/'private-pg18-windows-connection.env').write_text((root/'private-pg18-connection.env').read_text().replace('Port=55438;', 'Port='+str(server.getsockname()[1])+';'))
print('Owned loopback PostgreSQL stdio proxy ready',flush=True)
try:
 while not stop.exists():
  try:client,_=server.accept()
  except socket.timeout:continue
  accepted+=1;threading.Thread(target=relay,args=(client,),daemon=True).start()
finally:
 server.close()
 with gate:
  for client in active:
   try:client.shutdown(socket.SHUT_RDWR)
   except OSError:pass
  remaining=list(children)
 for process in remaining:
  try:process.terminate();process.wait(timeout=5)
  except (OSError,subprocess.TimeoutExpired):pass
 print(json.dumps({'status':'stopped','accepted_connections':accepted}),flush=True)
