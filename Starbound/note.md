## Starbound

```
mark@rwx:~/Desktop/Labs/PwnableTW/starbound$ file starbound
starbound: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=5a960d92ab1e8594d377bd96eb6ea49980f412a9, not stripped
mark@rwx:~/Desktop/Labs/PwnableTW/starbound$ checksec starbound
[*] '/home/mark/Desktop/Labs/PwnableTW/starbound/starbound'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    FORTIFY:    Enabled
    Stripped:   No
mark@rwx:~/Desktop/Labs/PwnableTW/starbound$
```

Just a little bit of reversing necessary, the vulnerability in the program gives us an oob function call primitive.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char nptr[256]; // [esp+10h] [ebp-104h] BYREF

  init();
  while ( 1 )
  {
    alarm(0x3Cu);
    menu();
    if ( !readn(nptr, 0x100u) )
      break;
    v3 = strtol(nptr, 0, 10);
    if ( !v3 )
      break;
    funcs.handlers[v3]();
  }
  do_bye();
  return 0;
}
```


We control `v3` and no size check is performed on it.

Interesting objects before the cmd handlers

```c
.bss:080580C4 ; int fd
.bss:080580C4 fd              dd ?                    ; DATA XREF: cmd_multiplayer_enable+9↑r
.bss:080580C4                                         ; cmd_multiplayer_enable+3E↑w ...
.bss:080580C8 ; char *rhost
.bss:080580C8 rhost           dd ?                    ; DATA XREF: init+150↑w
.bss:080580C8                                         ; cmd_set_ip+32↑r ...
.bss:080580CC is_autoview     dd ?                    ; DATA XREF: cmd_set_autoview↑r
.bss:080580CC                                         ; cmd_set_autoview+D↑w ...
.bss:080580D0 ; char player[128]
.bss:080580D0 player          db 80h dup(?)           ; DATA XREF: do_afk+3↑o
.bss:080580D0                                         ; init+1A8↑o ...
.bss:08058150 center          dd ?                    ; DATA XREF: cmd_view+4F↑r
.bss:08058150                                         ; init_map+A8↑w ...
.bss:08058154 ; cmd_table funcs
.bss:08058154 funcs           cmd_table <?>           ; DATA XREF: show_main_menu:loc_8048DEF↑w
.bss:08058154                                         ; show_multiplayer_menu:loc_8048EBE↑w ...
.bss:0805817C ; int (*menu)(void)
.bss:0805817C menu            dd ?                    ; DATA XREF: cmd_go_back↑w
.bss:0805817C                                         ; cmd_move↑w ...
.bss:0805817C _bss            ends
```

We can control `player` by making use of `cmd_set_name`

```c
ssize_t cmd_set_name()
{
  ssize_t n; // eax

  __printf_chk(1, "Enter your name: ");
  n = readn(player, 100u);
  *(n + 0x80580CF) = 0;
  return n;
}
```

To get leak I had to do a stack pivot by using gadget: `0x0804a171`

```
add esp, 0x10 ; pop ebx ; pop esi ; pop edi ; ret
```

The value after the pop instructions is user-controllable.

So i wrote ROPchain to leak libc and return to main.

Then i did the same and got a shell.

There was also a format string bug at `cmd_kill`

```c
void __noreturn cmd_kill()
{
  char v1[268]; // [esp+10h] [ebp-10Ch] BYREF

  __printf_chk(1, "Why???? ");
  v1[readn(v1, 256u) - 1] = 0;
  do_die(v1);
}

void __cdecl __noreturn do_die(const char *a1)
{
  int v1; // eax
  _BYTE buf[1036]; // [esp+20h] [ebp-40Ch] BYREF

  __printf_chk(1, a1);
  puts("");
  __printf_chk(1, "Save your record? (y/n)");
  read(0, buf, 0x400u);
  if ( buf[0] == 121 )
  {
    v1 = __sprintf_chk(buf, 1, 1024, "Map seed: %08X\nScore: %d\n", starg.param.seed, starg.param.score);
    memcpy(&buf[v1], dig, starg.param.size >> 1);
    do_send_record(buf, 0x400u);
  }
  do_bye();
  exit(0);
}
```

But because it uses `__printf_chk`, we can't use specifiers to perform writes.. but you can leak although you won't get so far because it `exit()`.

