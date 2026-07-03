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

A bit of fresher, it only has 3 functions we can make use of:

```
mark@rwx:~/Desktop/Labs/PwnableTW/realloc-rev$ ./re-alloc_revenge
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
🍊      RE Allocator      🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. Alloc               $
$   2. Realloc             $
$   3. Free                $
$   4. Exit                $
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice:
```

There's no `edit` function and the content of an allocated chunk isn't printed out.

`main` function:

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v3 = 0;
  init_proc();
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      __isoc99_scanf("%d", &v3);
      if ( v3 != 2 )
        break;
      reallocate();
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        rfree();
      }
      else
      {
        if ( v3 == 4 )
          _exit(0);
LABEL_13:
        puts("Invalid Choice");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_13;
      allocate();
    }
  }
}
```

`allocate` function:

```c
void allocate()
{
  unsigned __int64 idx; // [rsp+0h] [rbp-20h]
  unsigned __int64 size; // [rsp+8h] [rbp-18h]
  char *v2; // [rsp+18h] [rbp-8h]

  printf("Index:");
  idx = read_long();
  if ( idx > 1 || heap[idx] )
  {
    puts("Invalid !");
  }
  else
  {
    printf("Size:");
    size = read_long();
    if ( size <= 0x78 )
    {
      v2 = (char *)malloc(size);
      if ( v2 )
      {
        heap[idx] = v2;
        printf("Data:");
        heap[idx][read_input(heap[idx], (unsigned int)size)] = 0;
      }
      else
      {
        puts("alloc error");
      }
    }
    else
    {
      puts("Too large!");
    }
  }
}

__int64 __fastcall read_input(char *buf, unsigned int count)
{
  __int64 n; // rax

  LODWORD(n) = __read_chk(0LL, buf, count, count);
  if ( !(_DWORD)n )
  {
    puts("read error");
    _exit(1);
  }
  if ( buf[(int)n - 1] == 10 )
    buf[(int)n - 1] = 0;
  return (int)n;
}

__int64 read_long()
{
  char nptr[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  __read_chk(0LL, nptr, 16LL, 17LL);
  return atoll(nptr);
}
```

`reallocate` function:

```c
int reallocate()
{
  unsigned __int64 idx; // [rsp+8h] [rbp-18h]
  unsigned __int64 size; // [rsp+10h] [rbp-10h]
  char *v3; // [rsp+18h] [rbp-8h]

  printf("Index:");
  idx = read_long();
  if ( idx > 1 || !heap[idx] )
    return puts("Invalid !");
  printf("Size:");
  size = read_long();
  if ( size > 0x78 )
    return puts("Too large!");
  v3 = (char *)realloc(heap[idx], size);
  if ( !v3 )
    return puts("alloc error");
  heap[idx] = v3;
  printf("Data:");
  return read_input(heap[idx], (unsigned int)size);
}
```

`rfree` function:

```c
void rfree()
{
  unsigned __int64 v0; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v0 = read_long();
  if ( v0 > 1 )
  {
    puts("Invalid !");
  }
  else
  {
    realloc(heap[v0], 0LL);
    heap[v0] = 0LL;
  }
}
```

The bug is in `reallocate`, it doesn't check if `size` is equal to `0`, this enables us to free a chunk.

And because `free` returns `NULL` on free, then the check `if (!v3)` succeeds which makes it not to update the chunk `heap[idx] = v3`

This leads to a UAF.





