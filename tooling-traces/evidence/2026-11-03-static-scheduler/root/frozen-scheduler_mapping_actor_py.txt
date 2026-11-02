"""ADR0028 preloaded one-child actor. Never launches at import; collector calls after fork."""
import ctypes,json,os,struct,time
from pathlib import Path

def send(fd,value):
    raw=json.dumps(value,separators=(',',':')).encode();packet=struct.pack('<I',len(raw))+raw
    if len(raw)>65536:raise ValueError('Bounded actor message')
    while packet:
        n=os.write(fd,packet)
        if n<=0:raise RuntimeError('Actor pipe write')
        packet=packet[n:]

def actor(control,report,syscall):
    try:
        os.setgroups([]);os.setgid(1000);os.setuid(1000)
        if os.getresuid()!=(1000,1000,1000) or os.getresgid()!=(1000,1000,1000) or os.getgroups()!=[]:raise ValueError('Exact ordinary credentials')
        # Exactly one explicit PRE-ARM gettid establishes the local lease.
        tid=int(syscall(ctypes.c_long(186),*[ctypes.c_long(0)]*6));pid=os.getpid()
        if tid!=pid or tid<=0:raise ValueError('One native actor thread')
        send(report,dict(kind='ready',pid=pid,tid=tid,uid=list(os.getresuid()),gid=list(os.getresgid()),groups=os.getgroups(),prearm_gettid_calls=1,
            namespaces={n:os.readlink('/proc/self/ns/'+n) for n in ['pid','time','user']},python_image=str(Path('/proc/self/exe').resolve())))
        if os.read(control,1)!=b'G':raise ValueError('Exact parent arm release')
        before=time.monotonic_ns()
        result=int(syscall(ctypes.c_long(186),*[ctypes.c_long(0)]*6))
        after=time.monotonic_ns()
        send(report,dict(kind='result',pid=pid,tid=tid,gettid_return=result,armed_gettid_calls=1,before_monotonic_ns=before,after_monotonic_ns=after))
        if os.read(control,1)!=b'X':raise ValueError('Exact final barrier acknowledgment')
        send(report,dict(kind='joined_barrier',pid=pid));os._exit(0)
    except BaseException as error:
        try:send(report,dict(kind='error',type=type(error).__name__,message=str(error)))
        except BaseException:pass
        os._exit(1)
