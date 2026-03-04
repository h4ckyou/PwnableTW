## Bookwriter

```
mark@rwx:~/Desktop/Labs/PwnableTW/bookwriter$ file bookwriter
bookwriter: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8c3e466870c649d07e84498bb143f1bb5916ae34, stripped
mark@rwx:~/Desktop/Labs/PwnableTW/bookwriter$ checksec bookwriter
[*] '/home/mark/Desktop/Labs/PwnableTW/bookwriter/bookwriter'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
```

No PIE enabled

This is a heap challenge as you can tell from the menu

```
mark@rwx:~/Desktop/Labs/PwnableTW/bookwriter$ ./bookwriter
Welcome to the BookWriter !
Author :asdf
----------------------
      BookWriter      
----------------------
 1. Add a page        
 2. View a page       
 3. Edit a page       
 4. Information       
 5. Exit              
----------------------
Your choice :
```

The global variables are defined as this:

```c
char author[64];
char *books[8];
uint32_t sizes[8];
```
