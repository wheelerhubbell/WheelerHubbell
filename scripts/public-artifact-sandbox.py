#!/usr/bin/env python3
"""Run downloaded Python against in-memory public inputs only.
A seccomp syscall allowlist denies every filesystem open, network operation,
process creation and privilege/namespace operation. No namespace privilege needed.
Fixed interpreter dependencies are preloaded before installing the irreversible filter.
"""
import argparse,base64,builtins,ctypes,errno,hashlib,io,json,os,pathlib,re,resource,sys,time,urllib.request,urllib.parse,zlib
from jsonschema import Draft202012Validator
from cryptography.hazmat.primitives.serialization import load_der_public_key,Encoding,PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey,Ed25519PrivateKey

def main():
    if len(sys.argv)<3:raise RuntimeError('SANDBOX_ARGUMENTS_REQUIRED')
    directory=pathlib.Path(sys.argv[1]).resolve(strict=True);args=sys.argv[2:]
    files={}
    for p in directory.iterdir():
        if p.is_symlink() or not p.is_file() or p.stat().st_size>2_000_000:raise RuntimeError('PUBLIC_FILES_ONLY')
        files['/input/'+p.name]=p.read_bytes()
    if len(files)>8:raise RuntimeError('INPUT_LIMIT')
    program='/input/verifier.py';code=compile(files[program],program,'exec')
    'preload'.encode('utf-16be');'preload'.encode('utf-8')
    Draft202012Validator({'type':'object'}).validate({})
    k=Ed25519PrivateKey.generate();sig=k.sign(b'preload');k.public_key().verify(sig,b'preload');del k,sig
    argparse.ArgumentParser().parse_args([])
    lib=ctypes.CDLL('libseccomp.so.2',use_errno=True)
    lib.seccomp_init.argtypes=[ctypes.c_uint32];lib.seccomp_init.restype=ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p];lib.seccomp_syscall_resolve_name.restype=ctypes.c_int
    lib.seccomp_rule_add.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint]
    lib.seccomp_load.argtypes=[ctypes.c_void_p];lib.seccomp_release.argtypes=[ctypes.c_void_p]
    ctx=lib.seccomp_init(0x00050000|errno.EPERM)
    for name in ['read','write','writev','close','fstat','lseek','brk','mmap','mprotect','munmap','mremap','madvise','futex','clock_gettime','clock_nanosleep','nanosleep','getrandom','getpid','gettid','getuid','geteuid','getgid','getegid','rt_sigaction','rt_sigprocmask','rt_sigreturn','sigaltstack','sched_yield','exit','exit_group','restart_syscall']:
        number=lib.seccomp_syscall_resolve_name(name.encode())
        if number>=0 and lib.seccomp_rule_add(ctx,0x7fff0000,number,0)!=0:raise RuntimeError('SECCOMP_RULE_FAILED')
    resource.setrlimit(resource.RLIMIT_CPU,(20,20));resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    libc=ctypes.CDLL(None)
    if libc.prctl(38,1,0,0,0)!=0:raise RuntimeError('NO_NEW_PRIVS_FAILED')
    os.closerange(3,65536);os.environ.clear();sys.path=[];sys.dont_write_bytecode=True
    def public_open(path,mode='r',*a,**kw):
        name=os.fspath(path)
        if name not in files or mode not in ['r','rb','rt']:raise PermissionError('PUBLIC_READ_ONLY_INPUTS')
        return io.BytesIO(files[name]) if 'b' in mode else io.StringIO(files[name].decode(kw.get('encoding') or 'utf-8'))
    builtins.open=public_open;io.open=public_open
    if lib.seccomp_load(ctx)!=0:raise RuntimeError('SECCOMP_LOAD_FAILED')
    lib.seccomp_release(ctx);sys.argv=[program,*args]
    exec(code,{'__name__':'__main__','__file__':program})

if __name__=='__main__':main()
