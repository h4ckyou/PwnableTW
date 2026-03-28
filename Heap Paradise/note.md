## Heap Paradise 

```
mark@rwx:~/Desktop/Labs/PwnableTW/heap_paradise$ file heap_paradise
heap_paradise: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, for GNU/Linux 2.6.32, BuildID[sha1]=0f2c77e0e0c4e37c78f827f6ae317e208bbb202a, stripped
mark@rwx:~/Desktop/Labs/PwnableTW/heap_paradise$ checksec heap_paradise
[*] '/home/mark/Desktop/Labs/PwnableTW/heap_paradise/heap_paradise'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    FORTIFY:    Enabled
```

