## Heap Paradise 

<img width="596" height="342" alt="image" src="https://github.com/user-attachments/assets/99b959f1-4f6e-4ad6-be5d-1e452129c7da" />

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

Here's the decompilation of the two important functions

- allocate_chunk

```c
void allocate_chunk()
{
  int i; // [rsp+4h] [rbp-Ch]
  unsigned __int64 size; // [rsp+8h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    if ( i > 15 )
    {
      puts("You can't allocate anymore !");
      return;
    }
    if ( !chunks[i] )
      break;
  }
  printf("Size :");
  size = read_int();
  if ( size <= 0x78 )
  {
    chunks[i] = malloc(size);
    if ( !chunks[i] )
    {
      puts("Error!");
      exit(-1);
    }
    printf("Data :");
    read_to_buf(chunks[i], size);
  }
}
```

- free_chunk

```c
void free_chunk()
{
  __int64 v0; // [rsp+8h] [rbp-8h]

  printf("Index :");
  v0 = read_int();
  if ( v0 <= 15 )
    free(chunks[v0]);
}
```
