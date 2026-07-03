## Re-alloc Revenge

<img width="602" height="349" alt="image" src="https://github.com/user-attachments/assets/84d2613d-a053-4be2-867e-4f9577c33092" />

It's the same as [Re-alloc](https://github.com/h4ckyou/PwnableTW/blob/main/Re-alloc/note.md) only that this time around, all protections are enabled.

```
mark@rwx:~/Desktop/Labs/PwnableTW/realloc-rev$ checksec re-alloc_revenge
[*] '/home/mark/Desktop/Labs/PwnableTW/realloc-rev/re-alloc_revenge'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    Stripped:   No
mark@rwx:~/Desktop/Labs/PwnableTW/realloc-rev$
```

