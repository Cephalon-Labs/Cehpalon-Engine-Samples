import os,socket,sys,threading
connection=socket.create_connection(('127.0.0.1',55438),timeout=10)
connection.settimeout(None)
def upload():
 try:
  while True:
   data=os.read(sys.stdin.fileno(),65536)
   if not data:break
   connection.sendall(data)
 except (OSError,ValueError):pass
 finally:
  try:connection.shutdown(socket.SHUT_WR)
  except OSError:pass
threading.Thread(target=upload,daemon=True).start()
try:
 while True:
  data=connection.recv(65536)
  if not data:break
  sys.stdout.buffer.write(data);sys.stdout.buffer.flush()
finally:connection.close()
